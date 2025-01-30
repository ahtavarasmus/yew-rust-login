





use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::result::Error as DieselError;
use crate::{
    models::user_models::{User, NewUser},
    schema::users,
    schema::users::dsl::*,
    DbPool,
};

pub struct UserRepository {
    pool: DbPool
}

impl UserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // Check if a username exists
    pub fn username_exists(&self, search_username: &str) -> Result<bool, DieselError> {
        let mut conn = self.pool.get().expect("Failed to get DB connection");
        let existing_user: Option<User> = users::table
            .filter(users::username.eq(search_username))
            .first::<User>(&mut conn)
            .optional()?;
        Ok(existing_user.is_some())
    }

    // Create and insert a new user
    pub fn create_user(&self, new_user: NewUser) -> Result<(), DieselError> {
        let mut conn = self.pool.get().expect("Failed to get DB connection");
        diesel::insert_into(users::table)
            .values(&new_user)
            .execute(&mut conn)?;
        Ok(())
    }

    // Find a user by username
    pub fn find_by_username(&self, search_username: &str) -> Result<Option<User>, DieselError> {
        let mut conn = self.pool.get().expect("Failed to get DB connection");
        let user = users::table
            .filter(users::username.eq(search_username))
            .first::<User>(&mut conn)
            .optional()?;
        Ok(user)
    }

    // Get all users
    pub fn get_all_users(&self) -> Result<Vec<(i32, String, String)>, DieselError> {
        let mut conn = self.pool.get().expect("Failed to get DB connection");
        let users_list = users::table
            .select((users::id, users::username, users::email))
            .load::<(i32, String, String)>(&mut conn)?;
        Ok(users_list)
    }

    // Check if a user is an admin (username is 'rasmus')
    pub fn is_admin(&self, user_id: i32) -> Result<bool, DieselError> {
        let mut conn = self.pool.get().expect("Failed to get DB connection");
        let user = users::table
            .find(user_id)
            .first::<User>(&mut conn)?;

        Ok(user.username == "rasmus")
    }
    
}
