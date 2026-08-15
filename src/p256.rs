//! Dependency-free P-256 arithmetic.
//!
//! Curve parameters are defined by NIST SP 800-186 section 3.2.1.3.
//!
//! Fixed-width integer, field, scalar, and elliptic-curve point arithmetic
//! are implemented here. ECDH and ECDSA are layered on top in later slices.
//!
//! Uncompressed public-point encoding follows SEC 1 as profiled by
//! RFC 5480 section 2.2.

use std::{cmp::Ordering, error::Error, fmt};

pub const P256_FIELD_MODULUS: Uint256 = Uint256([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);

pub const P256_GROUP_ORDER: Uint256 = Uint256([
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
]);

pub const P256_CURVE_A: Uint256 = Uint256([
    0xffff_ffff_ffff_fffc,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);

pub const P256_CURVE_B: Uint256 = Uint256([
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
]);

pub const P256_GENERATOR_X: Uint256 = Uint256([
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
]);

pub const P256_GENERATOR_Y: Uint256 = Uint256([
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Uint256([u64; 4]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct WideUint512([u64; 8]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P256PointError {
    InvalidEncodingLength { length: usize },
    UnsupportedEncoding { prefix: u8 },
    CoordinateOutOfRange,
    PointNotOnCurve,
    IdentityCannotBeEncoded,
}

impl fmt::Display for P256PointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncodingLength { length } => {
                write!(
                    formatter,
                    "P-256 uncompressed point must contain 65 bytes, got {length}"
                )
            }
            Self::UnsupportedEncoding { prefix } => {
                write!(
                    formatter,
                    "unsupported P-256 point encoding prefix 0x{prefix:02x}"
                )
            }
            Self::CoordinateOutOfRange => {
                formatter.write_str("P-256 point coordinate is outside the field")
            }
            Self::PointNotOnCurve => formatter.write_str("P-256 point is not on the curve"),
            Self::IdentityCannotBeEncoded => {
                formatter.write_str("P-256 identity point has no uncompressed public-key encoding")
            }
        }
    }
}

impl Error for P256PointError {}

impl Uint256 {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    pub const fn limbs(self) -> [u64; 4] {
        self.0
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0_u64; 4];

        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = 32 - ((index + 1) * 8);

            *limb = u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("P-256 limb must contain eight bytes"),
            );
        }

        Self(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut output = [0_u8; 32];

        for (index, limb) in self.0.iter().enumerate() {
            let start = 32 - ((index + 1) * 8);

            output[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }

        output
    }

    pub fn overflowing_add(self, other: Self) -> (Self, bool) {
        let mut output = [0_u64; 4];
        let mut carry = false;

        for (index, output_limb) in output.iter_mut().enumerate() {
            let (sum, carry_a) = self.0[index].overflowing_add(other.0[index]);

            let carry_value = if carry { 1 } else { 0 };

            let (sum, carry_b) = sum.overflowing_add(carry_value);

            *output_limb = sum;
            carry = carry_a || carry_b;
        }

        (Self(output), carry)
    }

    pub fn overflowing_sub(self, other: Self) -> (Self, bool) {
        let mut output = [0_u64; 4];
        let mut borrow = false;

        for (index, output_limb) in output.iter_mut().enumerate() {
            let (difference, borrow_a) = self.0[index].overflowing_sub(other.0[index]);

            let borrow_value = if borrow { 1 } else { 0 };

            let (difference, borrow_b) = difference.overflowing_sub(borrow_value);

            *output_limb = difference;
            borrow = borrow_a || borrow_b;
        }

        (Self(output), borrow)
    }

    fn multiply_wide(self, other: Self) -> WideUint512 {
        let mut output = [0_u64; 8];

        for left_index in 0..4 {
            let mut carry = 0_u128;

            for right_index in 0..4 {
                let output_index = left_index + right_index;

                let product = u128::from(self.0[left_index]) * u128::from(other.0[right_index]);

                let accumulated = product + u128::from(output[output_index]) + carry;

                output[output_index] = accumulated as u64;
                carry = accumulated >> 64;
            }

            let mut output_index = left_index + 4;

            while carry != 0 {
                assert!(
                    output_index < output.len(),
                    "256-bit multiplication overflowed 512 bits"
                );

                let accumulated = u128::from(output[output_index]) + carry;

                output[output_index] = accumulated as u64;
                carry = accumulated >> 64;
                output_index += 1;
            }
        }

        WideUint512(output)
    }

    fn bit(self, index: usize) -> bool {
        let limb = index / 64;
        let offset = index % 64;

        ((self.0[limb] >> offset) & 1) != 0
    }
}

impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for (left, right) in self.0.iter().zip(&other.0).rev() {
            match left.cmp(right) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }

        Ordering::Equal
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WideUint512 {
    fn bit(self, index: usize) -> bool {
        let limb = index / 64;
        let offset = index % 64;

        ((self.0[limb] >> offset) & 1) != 0
    }
}

fn compare_five_limbs(left: &[u64; 5], right: &[u64; 5]) -> Ordering {
    for (left_limb, right_limb) in left.iter().zip(right).rev() {
        match left_limb.cmp(right_limb) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    Ordering::Equal
}

fn subtract_five_limbs(left: &mut [u64; 5], right: &[u64; 5]) {
    let mut borrow = false;

    for (left_limb, right_limb) in left.iter_mut().zip(right) {
        let (difference, borrow_a) = left_limb.overflowing_sub(*right_limb);

        let borrow_value = if borrow { 1 } else { 0 };

        let (difference, borrow_b) = difference.overflowing_sub(borrow_value);

        *left_limb = difference;
        borrow = borrow_a || borrow_b;
    }

    debug_assert!(!borrow);
}

fn shift_five_limbs_left_one(limbs: &mut [u64; 5]) {
    let mut carry = 0_u64;

    for limb in limbs {
        let next_carry = *limb >> 63;

        *limb = (*limb << 1) | carry;

        carry = next_carry;
    }

    debug_assert_eq!(carry, 0);
}

fn reduce_wide(value: WideUint512, modulus: Uint256) -> Uint256 {
    let modulus = [modulus.0[0], modulus.0[1], modulus.0[2], modulus.0[3], 0];

    let mut remainder = [0_u64; 5];

    for bit_index in (0..512).rev() {
        shift_five_limbs_left_one(&mut remainder);

        if value.bit(bit_index) {
            remainder[0] |= 1;
        }

        if compare_five_limbs(&remainder, &modulus) != Ordering::Less {
            subtract_five_limbs(&mut remainder, &modulus);
        }
    }

    debug_assert_eq!(remainder[4], 0);

    Uint256([remainder[0], remainder[1], remainder[2], remainder[3]])
}

fn reduce_uint(value: Uint256, modulus: Uint256) -> Uint256 {
    reduce_wide(
        WideUint512([value.0[0], value.0[1], value.0[2], value.0[3], 0, 0, 0, 0]),
        modulus,
    )
}

fn add_mod(left: Uint256, right: Uint256, modulus: Uint256) -> Uint256 {
    let (sum, carry) = left.overflowing_add(right);

    let carry = if carry { 1 } else { 0 };

    reduce_wide(
        WideUint512([sum.0[0], sum.0[1], sum.0[2], sum.0[3], carry, 0, 0, 0]),
        modulus,
    )
}

fn sub_mod(left: Uint256, right: Uint256, modulus: Uint256) -> Uint256 {
    if left >= right {
        left.overflowing_sub(right).0
    } else {
        let difference = right.overflowing_sub(left).0;

        modulus.overflowing_sub(difference).0
    }
}

fn mul_mod(left: Uint256, right: Uint256, modulus: Uint256) -> Uint256 {
    reduce_wide(left.multiply_wide(right), modulus)
}

fn pow_mod(base: Uint256, exponent: Uint256, modulus: Uint256) -> Uint256 {
    let mut result = Uint256::ONE;
    let base = reduce_uint(base, modulus);

    for bit_index in (0..256).rev() {
        result = mul_mod(result, result, modulus);

        if exponent.bit(bit_index) {
            result = mul_mod(result, base, modulus);
        }
    }

    result
}

fn invert_mod(value: Uint256, modulus: Uint256) -> Option<Uint256> {
    let value = reduce_uint(value, modulus);

    if value == Uint256::ZERO {
        return None;
    }

    let two = Uint256::from_limbs([2, 0, 0, 0]);

    let exponent = modulus.overflowing_sub(two).0;

    Some(pow_mod(value, exponent, modulus))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement(Uint256);

impl FieldElement {
    pub const ZERO: Self = Self(Uint256::ZERO);

    pub const ONE: Self = Self(Uint256::ONE);

    pub fn new(value: Uint256) -> Self {
        Self(reduce_uint(value, P256_FIELD_MODULUS))
    }

    pub const fn value(self) -> Uint256 {
        self.0
    }

    pub fn modular_add(self, other: Self) -> Self {
        Self(add_mod(self.0, other.0, P256_FIELD_MODULUS))
    }

    pub fn modular_subtract(self, other: Self) -> Self {
        Self(sub_mod(self.0, other.0, P256_FIELD_MODULUS))
    }

    pub fn modular_multiply(self, other: Self) -> Self {
        Self(mul_mod(self.0, other.0, P256_FIELD_MODULUS))
    }

    pub fn square(self) -> Self {
        self.modular_multiply(self)
    }

    pub fn invert(self) -> Option<Self> {
        invert_mod(self.0, P256_FIELD_MODULUS).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scalar(Uint256);

impl Scalar {
    pub const ZERO: Self = Self(Uint256::ZERO);

    pub const ONE: Self = Self(Uint256::ONE);

    pub fn new(value: Uint256) -> Self {
        Self(reduce_uint(value, P256_GROUP_ORDER))
    }

    pub const fn value(self) -> Uint256 {
        self.0
    }

    pub fn modular_add(self, other: Self) -> Self {
        Self(add_mod(self.0, other.0, P256_GROUP_ORDER))
    }

    pub fn modular_subtract(self, other: Self) -> Self {
        Self(sub_mod(self.0, other.0, P256_GROUP_ORDER))
    }

    pub fn modular_multiply(self, other: Self) -> Self {
        Self(mul_mod(self.0, other.0, P256_GROUP_ORDER))
    }

    pub fn invert(self) -> Option<Self> {
        invert_mod(self.0, P256_GROUP_ORDER).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AffinePoint {
    x: FieldElement,
    y: FieldElement,
}

/// Validated P-256 point.
///
/// The private representation prevents callers from constructing arbitrary
/// affine coordinates without passing curve validation first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct P256Point(Option<AffinePoint>);

impl P256Point {
    pub const IDENTITY: Self = Self(None);

    pub fn generator() -> Self {
        Self(Some(AffinePoint {
            x: FieldElement(P256_GENERATOR_X),
            y: FieldElement(P256_GENERATOR_Y),
        }))
    }

    pub fn from_coordinates(x: Uint256, y: Uint256) -> Result<Self, P256PointError> {
        if x >= P256_FIELD_MODULUS || y >= P256_FIELD_MODULUS {
            return Err(P256PointError::CoordinateOutOfRange);
        }

        let point = Self(Some(AffinePoint {
            x: FieldElement(x),
            y: FieldElement(y),
        }));

        if !point.is_on_curve() {
            return Err(P256PointError::PointNotOnCurve);
        }

        Ok(point)
    }

    pub fn is_identity(self) -> bool {
        self.0.is_none()
    }

    pub fn is_on_curve(self) -> bool {
        let Some(point) = self.0 else {
            return true;
        };

        let x_squared = point.x.square();

        let x_cubed = x_squared.modular_multiply(point.x);

        let ax = FieldElement(P256_CURVE_A).modular_multiply(point.x);

        let right = x_cubed
            .modular_add(ax)
            .modular_add(FieldElement(P256_CURVE_B));

        point.y.square() == right
    }

    pub fn coordinates(self) -> Option<(Uint256, Uint256)> {
        self.0.map(|point| (point.x.value(), point.y.value()))
    }

    pub fn add(self, other: Self) -> Self {
        JacobianPoint::from_point(self)
            .add(JacobianPoint::from_point(other))
            .to_point()
    }

    pub fn double(self) -> Self {
        JacobianPoint::from_point(self).double().to_point()
    }

    pub fn multiply(self, scalar: Scalar) -> Self {
        self.multiply_uint(scalar.value())
    }

    fn multiply_uint(self, scalar: Uint256) -> Self {
        let addend = JacobianPoint::from_point(self);
        let mut result = JacobianPoint::IDENTITY;

        for bit_index in (0..256).rev() {
            result = result.double();

            if scalar.bit(bit_index) {
                result = result.add(addend);
            }
        }

        result.to_point()
    }

    pub fn to_sec1_uncompressed(self) -> Result<[u8; 65], P256PointError> {
        let Some(point) = self.0 else {
            return Err(P256PointError::IdentityCannotBeEncoded);
        };

        let mut output = [0_u8; 65];

        output[0] = 0x04;
        output[1..33].copy_from_slice(&point.x.value().to_be_bytes());

        output[33..65].copy_from_slice(&point.y.value().to_be_bytes());

        Ok(output)
    }

    pub fn from_sec1_uncompressed(encoded: &[u8]) -> Result<Self, P256PointError> {
        if encoded.len() != 65 {
            return Err(P256PointError::InvalidEncodingLength {
                length: encoded.len(),
            });
        }

        if encoded[0] != 0x04 {
            return Err(P256PointError::UnsupportedEncoding { prefix: encoded[0] });
        }

        let x_bytes: [u8; 32] = encoded[1..33]
            .try_into()
            .expect("validated P-256 x coordinate must contain 32 bytes");

        let y_bytes: [u8; 32] = encoded[33..65]
            .try_into()
            .expect("validated P-256 y coordinate must contain 32 bytes");

        Self::from_coordinates(
            Uint256::from_be_bytes(x_bytes),
            Uint256::from_be_bytes(y_bytes),
        )
    }
}

pub fn p256_generator_multiply(scalar: Scalar) -> P256Point {
    P256Point::generator().multiply(scalar)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JacobianPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl JacobianPoint {
    const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    fn from_point(point: P256Point) -> Self {
        match point.0 {
            Some(point) => Self {
                x: point.x,
                y: point.y,
                z: FieldElement::ONE,
            },
            None => Self::IDENTITY,
        }
    }

    fn is_identity(self) -> bool {
        self.z == FieldElement::ZERO
    }

    fn to_point(self) -> P256Point {
        if self.is_identity() {
            return P256Point::IDENTITY;
        }

        let z_inverse = self
            .z
            .invert()
            .expect("non-identity Jacobian point must have invertible z");

        let z_inverse_squared = z_inverse.square();

        let x = self.x.modular_multiply(z_inverse_squared);

        let y = self
            .y
            .modular_multiply(z_inverse_squared)
            .modular_multiply(z_inverse);

        P256Point(Some(AffinePoint { x, y }))
    }

    fn double(self) -> Self {
        if self.is_identity() || self.y == FieldElement::ZERO {
            return Self::IDENTITY;
        }

        let delta = self.z.square();
        let gamma = self.y.square();

        let beta = self.x.modular_multiply(gamma);

        let alpha = field_triple(
            self.x
                .modular_subtract(delta)
                .modular_multiply(self.x.modular_add(delta)),
        );

        let eight_beta = field_double(field_double(field_double(beta)));

        let x = alpha.square().modular_subtract(eight_beta);

        let z = self
            .y
            .modular_add(self.z)
            .square()
            .modular_subtract(gamma)
            .modular_subtract(delta);

        let four_beta = field_double(field_double(beta));

        let eight_gamma_squared = field_double(field_double(field_double(gamma.square())));

        let y = alpha
            .modular_multiply(four_beta.modular_subtract(x))
            .modular_subtract(eight_gamma_squared);

        Self { x, y, z }
    }

    fn add(self, other: Self) -> Self {
        if self.is_identity() {
            return other;
        }

        if other.is_identity() {
            return self;
        }

        let z1_squared = self.z.square();
        let z2_squared = other.z.square();

        let u1 = self.x.modular_multiply(z2_squared);

        let u2 = other.x.modular_multiply(z1_squared);

        let s1 = self
            .y
            .modular_multiply(other.z)
            .modular_multiply(z2_squared);

        let s2 = other
            .y
            .modular_multiply(self.z)
            .modular_multiply(z1_squared);

        if u1 == u2 {
            if s1 != s2 {
                return Self::IDENTITY;
            }

            return self.double();
        }

        let h = u2.modular_subtract(u1);

        let i = field_double(h).square();

        let j = h.modular_multiply(i);

        let r = field_double(s2.modular_subtract(s1));

        let v = u1.modular_multiply(i);

        let x = r
            .square()
            .modular_subtract(j)
            .modular_subtract(field_double(v));

        let y = r
            .modular_multiply(v.modular_subtract(x))
            .modular_subtract(field_double(s1.modular_multiply(j)));

        let z = self
            .z
            .modular_add(other.z)
            .square()
            .modular_subtract(z1_squared)
            .modular_subtract(z2_squared)
            .modular_multiply(h);

        Self { x, y, z }
    }
}

fn field_double(value: FieldElement) -> FieldElement {
    value.modular_add(value)
}

fn field_triple(value: FieldElement) -> FieldElement {
    field_double(value).modular_add(value)
}

#[cfg(test)]
mod tests {
    use super::{
        FieldElement, P256_FIELD_MODULUS, P256_GENERATOR_X, P256_GENERATOR_Y, P256_GROUP_ORDER,
        P256Point, P256PointError, Scalar, Uint256, p256_generator_multiply,
    };

    #[test]
    fn uint256_big_endian_round_trip() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        assert_eq!(Uint256::from_be_bytes(bytes).to_be_bytes(), bytes);
    }

    #[test]
    fn uint256_addition_reports_carry() {
        let maximum = Uint256::from_limbs([u64::MAX; 4]);

        let (sum, carry) = maximum.overflowing_add(Uint256::ONE);

        assert_eq!(sum, Uint256::ZERO);
        assert!(carry);
    }

    #[test]
    fn uint256_subtraction_reports_borrow() {
        let (difference, borrow) = Uint256::ZERO.overflowing_sub(Uint256::ONE);

        assert_eq!(difference, Uint256::from_limbs([u64::MAX; 4]));

        assert!(borrow);
    }

    #[test]
    fn uint256_multiplication_spans_512_bits() {
        let maximum = Uint256::from_limbs([u64::MAX; 4]);

        let product = maximum.multiply_wide(maximum);

        assert_eq!(
            product.0,
            [
                0x0000_0000_0000_0001,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0xffff_ffff_ffff_fffe,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
            ]
        );
    }

    #[test]
    fn p256_field_reduces_modulus_to_zero() {
        assert_eq!(FieldElement::new(P256_FIELD_MODULUS), FieldElement::ZERO);
    }

    #[test]
    fn p256_field_addition_wraps_at_modulus() {
        let modulus_minus_one = P256_FIELD_MODULUS.overflowing_sub(Uint256::ONE).0;

        assert_eq!(
            FieldElement::new(modulus_minus_one).modular_add(FieldElement::ONE),
            FieldElement::ZERO
        );
    }

    #[test]
    fn p256_field_subtraction_wraps_at_modulus() {
        let modulus_minus_one = P256_FIELD_MODULUS.overflowing_sub(Uint256::ONE).0;

        assert_eq!(
            FieldElement::ZERO.modular_subtract(FieldElement::ONE),
            FieldElement::new(modulus_minus_one)
        );
    }

    #[test]
    fn p256_field_multiplication_reduces_correctly() {
        let modulus_minus_one = P256_FIELD_MODULUS.overflowing_sub(Uint256::ONE).0;

        let value = FieldElement::new(modulus_minus_one);

        assert_eq!(value.modular_multiply(value), FieldElement::ONE);
    }

    #[test]
    fn p256_field_inverse_round_trips() {
        let value = FieldElement::new(Uint256::from_limbs([2, 0, 0, 0]));

        let inverse = value.invert().unwrap();

        assert_eq!(value.modular_multiply(inverse), FieldElement::ONE);

        assert_eq!(FieldElement::ZERO.invert(), None);
    }

    #[test]
    fn p256_scalar_reduces_group_order_to_zero() {
        assert_eq!(Scalar::new(P256_GROUP_ORDER), Scalar::ZERO);
    }

    #[test]
    fn p256_scalar_arithmetic_wraps_at_group_order() {
        let order_minus_one = P256_GROUP_ORDER.overflowing_sub(Uint256::ONE).0;

        let value = Scalar::new(order_minus_one);

        assert_eq!(value.modular_add(Scalar::ONE), Scalar::ZERO);

        assert_eq!(Scalar::ZERO.modular_subtract(Scalar::ONE), value);

        assert_eq!(value.modular_multiply(value), Scalar::ONE);
    }

    #[test]
    fn p256_scalar_inverse_round_trips() {
        let value = Scalar::new(Uint256::from_limbs([3, 0, 0, 0]));

        let inverse = value.invert().unwrap();

        assert_eq!(value.modular_multiply(inverse), Scalar::ONE);

        assert_eq!(Scalar::ZERO.invert(), None);
    }

    #[test]
    fn p256_generator_is_valid_nist_point() {
        let generator = P256Point::generator();

        assert!(generator.is_on_curve());

        assert_eq!(
            generator.coordinates(),
            Some((P256_GENERATOR_X, P256_GENERATOR_Y))
        );
    }

    #[test]
    fn p256_rejects_noncanonical_coordinates() {
        assert_eq!(
            P256Point::from_coordinates(P256_FIELD_MODULUS, P256_GENERATOR_Y,),
            Err(P256PointError::CoordinateOutOfRange)
        );
    }

    #[test]
    fn p256_rejects_point_not_on_curve() {
        assert_eq!(
            P256Point::from_coordinates(Uint256::ONE, Uint256::ONE,),
            Err(P256PointError::PointNotOnCurve)
        );
    }

    #[test]
    fn p256_point_identity_behaves_as_group_identity() {
        let generator = P256Point::generator();

        assert_eq!(generator.add(P256Point::IDENTITY), generator);

        assert_eq!(P256Point::IDENTITY.add(generator), generator);

        assert_eq!(P256Point::IDENTITY.double(), P256Point::IDENTITY);
    }

    #[test]
    fn p256_generator_doubling_matches_known_coordinates() {
        let expected_x = Uint256::from_limbs([
            0xa60b_48fc_4766_9978,
            0xc089_69e2_77f2_1b35,
            0x8a52_3803_04b5_1ac3,
            0x7cf2_7b18_8d03_4f7e,
        ]);

        let expected_y = Uint256::from_limbs([
            0x9e04_b79d_2278_73d1,
            0xba7d_ade6_3ce9_8229,
            0x293d_9ac6_9f74_30db,
            0x0777_5510_db8e_d040,
        ]);

        let generator = P256Point::generator();

        assert_eq!(
            generator.double().coordinates(),
            Some((expected_x, expected_y))
        );

        assert_eq!(generator.add(generator), generator.double());
    }

    #[test]
    fn p256_scalar_multiplication_matches_doubling() {
        let two = Scalar::new(Uint256::from_limbs([2, 0, 0, 0]));

        assert_eq!(
            P256Point::generator().multiply(two),
            P256Point::generator().double()
        );

        assert_eq!(
            p256_generator_multiply(two),
            P256Point::generator().double()
        );
    }

    #[test]
    fn p256_generator_has_expected_group_order() {
        assert!(
            P256Point::generator()
                .multiply_uint(P256_GROUP_ORDER)
                .is_identity()
        );
    }

    #[test]
    fn p256_point_plus_inverse_is_identity() {
        let negative_y = P256_FIELD_MODULUS.overflowing_sub(P256_GENERATOR_Y).0;

        let negative_generator = P256Point::from_coordinates(P256_GENERATOR_X, negative_y).unwrap();

        assert!(P256Point::generator().add(negative_generator).is_identity());
    }

    #[test]
    fn p256_sec1_uncompressed_generator_round_trips() {
        let generator = P256Point::generator();

        let encoded = generator.to_sec1_uncompressed().unwrap();

        assert_eq!(encoded[0], 0x04);

        assert_eq!(&encoded[1..33], &P256_GENERATOR_X.to_be_bytes());

        assert_eq!(&encoded[33..65], &P256_GENERATOR_Y.to_be_bytes());

        assert_eq!(
            P256Point::from_sec1_uncompressed(&encoded).unwrap(),
            generator
        );
    }

    #[test]
    fn p256_sec1_rejects_invalid_prefix() {
        let mut encoded = P256Point::generator().to_sec1_uncompressed().unwrap();

        encoded[0] = 0x02;

        assert_eq!(
            P256Point::from_sec1_uncompressed(&encoded),
            Err(P256PointError::UnsupportedEncoding { prefix: 0x02 })
        );
    }

    #[test]
    fn p256_sec1_rejects_wrong_length() {
        assert_eq!(
            P256Point::from_sec1_uncompressed(&[0x04; 64]),
            Err(P256PointError::InvalidEncodingLength { length: 64 })
        );
    }

    #[test]
    fn p256_sec1_rejects_invalid_curve_point() {
        let mut encoded = [0_u8; 65];

        encoded[0] = 0x04;

        encoded[32] = 1;
        encoded[64] = 1;

        assert_eq!(
            P256Point::from_sec1_uncompressed(&encoded),
            Err(P256PointError::PointNotOnCurve)
        );
    }

    #[test]
    fn p256_identity_cannot_be_encoded_as_public_key() {
        assert_eq!(
            P256Point::IDENTITY.to_sec1_uncompressed(),
            Err(P256PointError::IdentityCannotBeEncoded)
        );
    }
}
