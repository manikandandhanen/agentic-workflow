import type { MigrationContext, ReversibleMigration } from '../migration-types';
 
export class AddTenentIdToWorkflow1734000000000 implements ReversibleMigration {
    async up({ escape, runQuery }: MigrationContext) {
        const tableName = escape.tableName('workflow_entity');
        const columnName = escape.columnName('tenentID');
 
        // varchar(255) is fine for a tenant id / dummy for now
        await runQuery(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} VARCHAR(255)`);
    }
 
    async down({ escape, runQuery }: MigrationContext) {
        const tableName = escape.tableName('workflow_entity');
        const columnName = escape.columnName('tenentID');
 
        await runQuery(`ALTER TABLE ${tableName} DROP COLUMN ${columnName}`);
    }
}