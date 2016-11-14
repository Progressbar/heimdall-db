extern crate rusqlite;

use ::std::borrow::Cow;

/// Contains information about member of Progressbar hackerspace.
#[derive(Eq, PartialEq, Debug)]
pub struct Member {
    /// User ID from Progressbar website
    pub uid: u32,
    /// If this is true, the user can add and remove users.
    pub can_manage_users: bool,
    /// How much user has to wait before he can enter.
    pub ban_time: Option<i64>,
    /// The last time user unsuccessfully attempted to enter.
    pub last_open_attempt: Option<i64>,
    /// When this user activates automatic mode, it will self-deactivate if it wasn't used during
    /// last `max_auto_inactive` seconds.
    pub max_auto_inactive: i64,
    /// The last time (Unix timestamp) user entered. None if he never did.
    pub last_enter_time: Option<i64>,
    /// The last time (Unix timestamp) user left. None if he never did.
    pub last_leave_time: Option<i64>,
}

impl Member {
    /// Helper function executes prepared statement with self fields bound.
    fn exec_stmt(&self, stmt: &mut ::rusqlite::Statement) -> ::rusqlite::Result<()> {
        let uid = self.uid as i64;
        stmt.execute(&[&uid, &self.can_manage_users, &self.ban_time, &self.last_open_attempt, &self.max_auto_inactive, &self.last_enter_time, &self.last_leave_time])
            .map(|_| ())
    }

    /// Inserts `Member` into database. Fails if he already exits.
    pub fn insert(&self, conn: &mut ::rusqlite::Connection) -> ::rusqlite::Result<()> {
        let mut stmt = try!(conn.prepare(
            "INSERT INTO members (uid, manager, ban_time, last_attempt, max_auto, last_enter, last_leave)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        ));

        self.exec_stmt(&mut stmt)
    }

    /// Inserts `Member` into database. Replaces old one if he does already exist.
    pub fn replace(&self, conn: &mut ::rusqlite::Connection) -> ::rusqlite::Result<()> {
        let mut stmt = try!(conn.prepare(
            "REPLACE INTO members (uid, manager, ban_time, last_attempt, max_auto, last_enter, last_leave)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        ));

        self.exec_stmt(&mut stmt)
    }

    /// Updates `Member` in database. Fails if he doesn't exist.
    pub fn update(&self, conn: &mut ::rusqlite::Connection) -> ::rusqlite::Result<()> {
        let mut stmt = try!(conn.prepare(
            "UPDATE members
             SET manager = ?2, ban_time = ?3, last_attempt = ?4, max_auto = ?5, last_enter = ?6, last_leave = ?7
             WHERE uid = ?1"
        ));

        self.exec_stmt(&mut stmt)
    }

    /// Deletes `Member` from database. Returns Ok(false) if it didn't exist in the first place.
    pub fn delete(&self, conn: &mut ::rusqlite::Connection) -> ::rusqlite::Result<bool> {
        let mut stmt = try!(conn.prepare(
            "DELETE FROM members
             WHERE uid = ?"
        ));

        let uid = self.uid as i64;
        stmt.execute(&[&uid])
            .map(|n| n == 1)
    }
}

/// Contains data about tag. Used for insertion only (because not all fields are needed for
/// authentication).
pub struct Tag<'id, 'adata> {
    /// Tag ID
    pub id: Cow<'id, [u8]>,
    /// User ID. Same as on Progressbar website.
    pub uid: u32,
    /// Code for method of authentication. Purposefully not enum, because it's meant to be a raw
    /// type.
    pub auth_method: u32,
    /// Arbitrary data if needed for authentication. (None means no additional authentication.)
    pub auth_data: Cow<'adata, [u8]>,
}

// TODO: impl<'a, 'b> Tag<'a, 'b>

/// Contains Error types and associated functions.
mod error {
    use ::std::error::Error;
    use ::std::fmt;
    use ::std::fmt::{Display, Formatter};

    /// Error returned when tag can't be identified.
    #[derive(Debug)]
    pub enum IdentificationError<Tae: Error> {
        /// Database retrieval failed
        DatabaseError(::rusqlite::Error),
        /// Additional authentication of tag failed
        TagAuthenticationError(Tae),
        /// Tag isn't in database
        TagNotFound,
    }

    impl<E: Error> Error for IdentificationError<E> {
        fn description(&self) -> &str {
            "failed to identify user"
        }

        fn cause(&self) -> Option<&Error> {
            use self::IdentificationError::*;

            match *self {
                DatabaseError(ref e) => Some(e),
                TagAuthenticationError(ref e) => Some(e),
                TagNotFound => None,
            }
        }
    }

    impl<E: Error> Display for IdentificationError<E> {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            match *self {
                IdentificationError::TagNotFound => write!(f, "{}: tag not found.", self.description()),
                                                                     // Both cases return Some
                ref e => write!(f, "{}: {}", e.description(), e.cause().unwrap()),
            }
        }
    }

    impl<E: Error> From<::rusqlite::Error> for IdentificationError<E> {
        fn from(err: ::rusqlite::Error) -> Self {
            IdentificationError::DatabaseError(err)
        }
    }
}

use error::IdentificationError;

/// Attempts to retrieve tag from database and performs additional authentication (via callback)
pub fn identify_user<'conn, 'tag, E, Cb>(connection: &'conn mut rusqlite::Connection, tag_id: &'tag [u8], mut callback: Cb) -> Result<Member, IdentificationError<E>> where E: ::std::error::Error, Cb: FnMut(u32, &[u8]) -> Result<(), E> {
    let mut stmt = try!(
        connection.prepare(
            "SELECT t.auth_method, t.auth_data, m.uid, m.manager, m.ban_time, last_attempt, max_auto, last_enter, last_leave
            FROM tags t
            INNER JOIN members m
            ON t.uid = m.uid
            WHERE t.tag_id = ?"
        )
    );
    let mut rows = try!(stmt.query_map(&[&tag_id], |row| {
        let auth_data = row.get::<_, Option<Vec<u8>>>(1);
                      // If auth data isn't present we skip additional tag authentication.
        auth_data.map_or(Ok(()), |auth_data| { callback(row.get::<_, i64>(0) as u32, &auth_data) }).map(|_| Member {
            uid: row.get::<_, i64>(2) as u32,
            can_manage_users: row.get(3),
            ban_time: row.get(4),
            last_open_attempt: row.get(5),
            max_auto_inactive: row.get(6),
            last_enter_time: row.get(7),
            last_leave_time: row.get(8),
        }).map_err(IdentificationError::TagAuthenticationError)
    }));

    try!(rows
         .next()
         .ok_or(IdentificationError::TagNotFound)
         .and_then(|r| r.map_err(Into::into))
    )
}

/// Creates needed tables for Heimdall to work.
pub fn create_tables(conn: &mut ::rusqlite::Connection) -> ::rusqlite::Result<()> {
        try!(conn.execute(
            "CREATE TABLE tags (
             tag_id VARBINARY(32) NOT NULL PRIMARY KEY,
             uid    INTEGER NOT NULL,
             auth_method INTEGER,
             auth_data BLOB
            )",
            &[]
        ));

        conn.execute(
            "CREATE TABLE members (
             uid          INTEGER NOT NULL PRIMARY KEY,
             manager      BOOLEAN NOT NULL,
             ban_time     INTEGER,
             last_attempt INTEGER,
             max_auto     INTEGER NOT NULL,
             last_enter   INTEGER,
             last_leave   INTEGER
            )",
            &[]
        ).map(|_| ())
}

#[cfg(test)]
mod tests {
    #[test]
    fn create_tables() {
        let mut conn = ::rusqlite::Connection::open_in_memory().unwrap();
        ::create_tables(&mut conn).unwrap();
    }

    #[test]
    fn identify() {
        let mut conn = ::rusqlite::Connection::open_in_memory().unwrap();
        ::create_tables(&mut conn).unwrap();

        let tag = [0, 1, 2, 3, 4];

        conn.execute(
            "INSERT INTO tags (tag_id, uid, auth_method, auth_data)
             VALUES (?, 42, 0, NULL)",
            &[&(&tag as &[u8])]
        ).unwrap();

        conn.execute(
            "INSERT INTO members (uid, manager, ban_time, last_attempt, max_auto, last_enter, last_leave)
             VALUES (42, 0, NULL, NULL, 1800, NULL, NULL)",
            &[]
        ).unwrap();

        let member = ::identify_user(&mut conn, &tag, |_, _| { ::std::result::Result::Ok::<_, ::std::io::Error>(()) }).unwrap();

        assert_eq!(member, ::Member {
            uid: 42,
            can_manage_users: false,
            ban_time: None,
            last_open_attempt: None,
            max_auto_inactive: 1800,
            last_enter_time: None,
            last_leave_time: None,
        });
    }

    #[test]
    fn table_ops() {
        let mut conn = ::rusqlite::Connection::open_in_memory().unwrap();
        ::create_tables(&mut conn).unwrap();

        let member = ::Member {
            uid: 42,
            can_manage_users: false,
            ban_time: None,
            last_open_attempt: None,
            max_auto_inactive: 1800,
            last_enter_time: None,
            last_leave_time: None,
        };

        member.insert(&mut conn).unwrap();
        member.insert(&mut conn).unwrap_err();

        member.replace(&mut conn).unwrap();

        assert!(member.delete(&mut conn).unwrap());
        assert!(!member.delete(&mut conn).unwrap());

        member.insert(&mut conn).unwrap();
        member.delete(&mut conn).unwrap();
    }
}
