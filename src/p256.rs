//! Dependency-free P-256 arithmetic.
//!
//! Curve parameters are defined by NIST SP 800-186 section 3.2.1.3.
//!
//! This module begins with correctness-oriented fixed-width integer,
//! modular-field, and scalar arithmetic. Higher-level point operations,
//! ECDH, and ECDSA are layered on top in later slices.

use std::cmp::Ordering;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Uint256([u64; 4]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct WideUint512([u64; 8]);

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

#[cfg(test)]
mod tests {
    use super::{FieldElement, P256_FIELD_MODULUS, P256_GROUP_ORDER, Scalar, Uint256};

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
}
