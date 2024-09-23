//! Model of the 'UploadedFiles' table

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "UploadedFiles")]
/// Main model that is used
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i64,
    pub filename: String,
    pub location: Option<String>,
    pub hash: Option<String>,
    #[sea_orm(column_name = "virustotalResult")]
    pub virustotal_result: Option<String>,
    #[sea_orm(column_name = "attackerId")]
    pub attacker_id: Option<i64>,
    pub size: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
/// Represents the relation to other tables
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::attacker::Entity",
        from = "Column::AttackerId",
        to = "super::attacker::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Attacker,
}

impl Related<super::attacker::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Attacker.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
