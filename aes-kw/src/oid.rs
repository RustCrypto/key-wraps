use const_oid::{AssociatedOid, ObjectIdentifier};

impl AssociatedOid for super::KekAes128 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5");
}

impl AssociatedOid for super::KekAes192 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25");
}

impl AssociatedOid for super::KekAes256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45");
}
