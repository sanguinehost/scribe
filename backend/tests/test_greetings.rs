#[test]
fn see_type() {
    let opt: crate::models::OptionalStringArray = Default::default();
    let x: () = opt.0;
}
