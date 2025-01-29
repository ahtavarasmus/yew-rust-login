use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::result::Error as DieselError;
use crate::{
    models::user_models::{User},
    schema::users::dsl::*
};

pub struct UserRepository;

impl UserRepository {
    pub fn find_by_username(conn: &mut SqliteConnection, search_username: &str) -> Result<User, DieselError> {
        users.filter(username.eq(username))
            .first(conn)
    }
}
