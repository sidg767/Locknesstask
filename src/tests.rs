extern crate alloc;

use crate::helpers::Error;
use crate::{decrypt, encrypt};
use alloc::{format, string::String};
use generic_ec::{Curve, Point, curves::*};
#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::Scalar;
    use rand::thread_rng;
    // Thread_rng() is better than custom RNG, didn't use deterministic RNG because we don't test ct values
    // roundtrip basically ensures that decrypt(encrypt(msg)) == msg
    fn roundtrip<E: Curve>() -> Result<(), String> {
        let mut rng = thread_rng();
        let sk = Scalar::<E>::random(&mut rng);
        let pk = Point::generator() * &sk;

        //tests different msg types like empty, ascii, all zeroes and all 0xff
        for msg in [&[][..], b"hello", &[0u8; 64], &[0xffu8; 127]] {
            let ct = encrypt(msg, &pk, &mut rng);
            let decrypted =
                decrypt::<E>(&sk, &ct).map_err(|e| format!("decryption failed: {:?}", e))?;
            if decrypted.as_slice() != msg {
                return Err(format!(
                    "roundtrip mismatch:\nexpected: {:02x?}\nactual:   {:02x?}",
                    msg, decrypted
                ));
            }
        }

        Ok(())
    }

    /// Generic Roundtrip tests on the three curves
    #[test]
    fn roundtrip_ed25519() -> Result<(), String> {
        roundtrip::<Ed25519>()
    }
    #[test]
    fn roundtrip_secp256k1() -> Result<(), String> {
        roundtrip::<Secp256k1>()
    }
    #[test]
    fn roundtrip_secp384r1() -> Result<(), String> {
        roundtrip::<Secp384r1>()
    }

    /// validates deterministic test vectors
    fn check_vector<E: Curve>(ct_hex: &str, pt_hex: &str) -> Result<(), String> {
        let sk = Scalar::<E>::from(65537u64);
        // hex is better in test vectors as raw binary data hard to embed and read
        let ct = hex::decode(ct_hex)
            .map_err(|e| format!("failed to decode ciphertext hex vector: {}", e))?;

        let expected = hex::decode(pt_hex)
            .map_err(|e| format!("failed to decode plaintext hex vector: {}", e))?;

        let decrypted =
            decrypt::<E>(&sk, &ct).map_err(|e| format!("vector decryption failed: {:?}", e))?;

        if decrypted != expected {
            return Err(format!(
                "vector mismatch:\nexpected: {:02x?}\nactual:   {:02x?}",
                expected, decrypted
            ));
        }

        Ok(())
    }
    ///pt is plaintext
    #[test]
    fn vec1() -> Result<(), String> {
        check_vector::<Ed25519>(
            "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b16021c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
    }

    #[test]
    fn vec2() -> Result<(), String> {
        check_vector::<Ed25519>(
            "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e575cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    }

    #[test]
    fn vec3() -> Result<(), String> {
        check_vector::<Ed25519>(
            "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98067495fdb24b782dac9da5c0eb246c9fb15c00593e",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c206a6520766f757320646f6e6e65206c6120766965",
        )
    }

    #[test]
    fn vec4() -> Result<(), String> {
        check_vector::<Secp256k1>(
            "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad4940c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395f1",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
    }

    #[test]
    fn vec5() -> Result<(), String> {
        check_vector::<Secp256k1>(
            "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d0660ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf6",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    }

    #[test]
    fn vec6() -> Result<(), String> {
        check_vector::<Secp256k1>(
            "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd758795f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c206a6520766f757320646f6e6e65206c6120766965",
        )
    }

    #[test]
    fn vec7() -> Result<(), String> {
        check_vector::<Secp384r1>(
            "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497afb8156b91c3f5baa12b4d81b5f44f2eb402399e501ed395e834c44d5c85008ef0a8b281240c5d409e4d1b85a586e493332",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
    }

    #[test]
    fn vec8() -> Result<(), String> {
        check_vector::<Secp384r1>(
            "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa5abb536caf174cc3258bf387f3e72e496c018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    }

    #[test]
    fn vec9() -> Result<(), String> {
        check_vector::<Secp384r1>(
            "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a3e79b4895fe83593a0cbe39b4010d96c63d39a10133ef7f68aabfc63253f4537337539a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b7f773eb58706",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c206a6520766f757320646f6e6e65206c6120766965",
        )
    }

    #[test]
    fn too_short() -> Result<(), String> {
        let sk = Scalar::<Secp256k1>::zero();
        let empty_result = decrypt::<Secp256k1>(&sk, &[]);
        if !matches!(empty_result, Err(Error::LessBytes)) {
            return Err(format!(
                "expected LessBytes for empty ciphertext, got: {:?}",
                empty_result
            ));
        }

        let short_result = decrypt::<Secp256k1>(&sk, &[0u8; 10]);
        if !matches!(short_result, Err(Error::LessBytes)) {
            return Err(format!(
                "expected LessBytes for short ciphertext, got: {:?}",
                short_result
            ));
        }
        Ok(())
    }

    #[test]
    fn invalid_point() -> Result<(), String> {
        let sk = Scalar::<Secp256k1>::zero();
        let result = decrypt::<Secp256k1>(&sk, &[0xffu8; 33]);
        if !matches!(result, Err(Error::WrongPoint)) {
            return Err(format!("expected WrongPoint error, got: {:?}", result));
        }
        Ok(())
    }
}
