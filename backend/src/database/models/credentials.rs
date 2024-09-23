//! Model of the 'Credentials' table
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "Credentials")]
/// Main model that is used
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i64,
    pub username: String,
    pub password: String,
    pub count: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
/// Represents the relation to other tables
pub enum Relation {
    #[sea_orm(has_many = "super::attacker::Entity")]
    Attacker,
}

impl Related<super::attacker::Entity> for Entity {
    fn to() -> RelationDef {
        super::attacker_to_credentials::Relation::Attacker.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::attacker_to_credentials::Relation::Credentials
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
