//! Model of the 'AttackersToCredentials' table

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "AttackersToCredentials")]
/// Main model that is used
pub struct Model {
    #[sea_orm(column_name = "attackerId", primary_key, auto_increment = false)]
    pub attacker_id: i64,
    #[sea_orm(column_name = "credentialsId", primary_key, auto_increment = false)]
    pub credentials_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
/// Represents the relation to other tables
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::attacker::Entity",
        from = "Column::AttackerId",
        to = "super::attacker::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Attacker,
    #[sea_orm(
        belongs_to = "super::credentials::Entity",
        from = "Column::CredentialsId",
        to = "super::credentials::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Credentials,
}

impl Related<super::attacker::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Attacker.def()
    }
}

impl Related<super::credentials::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credentials.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
