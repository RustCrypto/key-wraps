use const_oid::{AssociatedOid, ObjectIdentifier};

use super::{KekAes128, KekAes192, KekAes256};

impl AssociatedOid for KekAes128 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5");
}

impl AssociatedOid for KekAes192 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25");
}

impl AssociatedOid for KekAes256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45");
}
