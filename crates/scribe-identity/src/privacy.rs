use crate::db::DbId;

pub fn loggable_user_id(id: DbId) -> String {
    format!("{}", id.simple())
}
