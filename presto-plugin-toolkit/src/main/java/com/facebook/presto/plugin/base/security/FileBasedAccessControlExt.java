/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.plugin.base.security;

import com.facebook.presto.plugin.base.security.TableWithColumnsAccessControlRule.TablePrivilege;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.connector.ConnectorAccessControl;
import com.facebook.presto.spi.connector.ConnectorTransactionHandle;
import com.facebook.presto.spi.security.AccessDeniedException;
import com.facebook.presto.spi.security.Identity;
import com.facebook.presto.spi.security.Privilege;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import io.airlift.json.ObjectMapperProvider;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.facebook.presto.plugin.base.security.TableWithColumnsAccessControlRule.TablePrivilege.DELETE;
import static com.facebook.presto.plugin.base.security.TableWithColumnsAccessControlRule.TablePrivilege.GRANT_SELECT;
import static com.facebook.presto.plugin.base.security.TableWithColumnsAccessControlRule.TablePrivilege.INSERT;
import static com.facebook.presto.plugin.base.security.TableWithColumnsAccessControlRule.TablePrivilege.OWNERSHIP;
import static com.facebook.presto.plugin.base.security.TableWithColumnsAccessControlRule.TablePrivilege.SELECT;
import static com.facebook.presto.spi.security.AccessDeniedException.denyAddColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateView;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDeleteTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropView;
import static com.facebook.presto.spi.security.AccessDeniedException.denyGrantTablePrivilege;
import static com.facebook.presto.spi.security.AccessDeniedException.denyInsertTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRevokeTablePrivilege;
import static com.facebook.presto.spi.security.AccessDeniedException.denySelectTable;
import static java.lang.String.format;

public class FileBasedAccessControlExt
        implements ConnectorAccessControl
{
    private static final String INFORMATION_SCHEMA_NAME = "information_schema";

    private final List<SchemaAccessControlRule> schemaRules;
    private final List<TableWithColumnsAccessControlRule> tableRules;
    private final List<SessionPropertyAccessControlRule> sessionPropertyRules;
    private static final Logger log = Logger.getLogger(FileBasedAccessControlExt.class.getName());
    private final Boolean enableColumnsSecurity;
    private final Boolean logDecisions;

    @Inject
    public FileBasedAccessControlExt(FileBasedAccessControlWithColumnsConfig config)
            throws IOException
    {
        log.info("file based access control, file=" + config.getConfigFile() + ", enable-columns-security=" + config.isEnableColumnsSecurity());
        AccessControlRulesWithColumns rules = parse(Files.readAllBytes(Paths.get(config.getConfigFile())));
        this.enableColumnsSecurity = config.isEnableColumnsSecurity();
        this.logDecisions = config.isEnableLogDecisions();
        this.schemaRules = rules.getSchemaRules();
        this.tableRules = rules.getTableRules();
        this.sessionPropertyRules = rules.getSessionPropertyRules();
    }

    private static AccessControlRulesWithColumns parse(byte[] json)
    {
        ObjectMapper mapper = new ObjectMapperProvider().get()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        Class<AccessControlRulesWithColumns> javaType = AccessControlRulesWithColumns.class;
        try {
            return mapper.readValue(json, javaType);
        }
        catch (IOException e) {
            throw new IllegalArgumentException(format("Extended File Rule: Invalid JSON string for %s", javaType), e);
        }
    }

    @Override
    public void checkCanShowSchemas(ConnectorTransactionHandle transactionHandle, Identity identity)
    {
    }

    @Override
    public Set<String> filterSchemas(ConnectorTransactionHandle transactionHandle, Identity identity, Set<String> schemaNames)
    {
        log.info("task=catalog-filter-schemas, identity=" + identity.getUser() + ",\n schemas=\"" + String.join(", ", schemaNames)
                + "\"");
        Set<String> allowedSchemas = schemaNames.stream().filter(schema -> findAccessSchema(identity, schema).isPresent()).collect(Collectors.toSet());
        log.info("task=catalog-filter-schemas, identity=" + identity.getUser() + ", allowed=" + String.join(",", allowedSchemas));
        return allowedSchemas;
    }

    @Override
    public void checkCanCreateTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!isDatabaseOwner(identity, tableName.getSchemaName())) {
            denyCreateTable(tableName.toString());
        }
    }

    @Override
    public void checkCanDropTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyDropTable(tableName.toString());
        }
    }

    @Override
    public void checkCanShowTablesMetadata(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName)
    {
    }


    private Optional<SchemaAccessControlRule> findAccessSchema(Identity identity, String schemaName)
    {
        for (SchemaAccessControlRule rule : schemaRules) {
            Optional<Boolean> allowed = rule.match(identity.getUser(), schemaName);
            if (allowed.isPresent() && allowed.get()) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }


    @Override
    public Set<SchemaTableName> filterTables(ConnectorTransactionHandle transactionHandle, Identity identity, Set<SchemaTableName> tableNames) {
        if (logDecisions) {
            log.info("task=catalog-filter-tables, identity=" + identity.getUser()
                    + ", tables=\"" + tableNames.stream().map(f -> f.getSchemaName() + "." + f.getTableName()).collect(Collectors.joining(", "))
                    + "\"");
        }
        Set<String> accessibleSchemas = filterSchemas(transactionHandle, identity, tableNames.stream().map(schemaTable -> schemaTable.getSchemaName()).collect(Collectors.toSet()));
        Set<SchemaTableName> allowedTables = tableNames.stream()
                .filter(tableName -> accessibleSchemas.contains(tableName.getSchemaName()))
                .filter(tableName -> checkTablePermission(identity, tableName))
                .collect(Collectors.toSet());
        if (logDecisions) {
            log.info("task=catalog-filter-tables, identity=" + identity.getUser()
                    + ", allowed-tables=" + allowedTables.stream().map(a -> a.getSchemaName() + "." + a.getTableName()).collect(Collectors.joining(",")));
        }
        return allowedTables;
    }

    @Override
    public void checkCanRenameTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName, SchemaTableName newTableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyRenameTable(tableName.toString(), newTableName.toString());
        }
    }

    @Override
    public void checkCanAddColumn(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyAddColumn(tableName.toString());
        }
    }

    @Override
    public void checkCanDropColumn(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyDropColumn(tableName.toString());
        }
    }

    @Override
    public void checkCanRenameColumn(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyRenameColumn(tableName.toString());
        }
    }

    @Override
    public void checkCanSelectFromColumns(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName, Set<String> columnNames)
    {
        if (enableColumnsSecurity) {
            log.info("task=catalog-check-column, identity=" + identity.getUser() + ",\n table=\"" + tableName.getSchemaName() + "." + tableName.getTableName() + "\", columns=\"" + String.join(",", columnNames)
                    + "\"");
            // TODO: Implement column level permissions
            if (!checkTablePermission(identity, tableName, SELECT)) {
                denySelectTable(tableName.toString());
            }

            Optional<TableWithColumnsAccessControlRule> tableRule = tableRules.stream().filter(tr -> {
                Optional<Set<TablePrivilege>> privileges = tr.match(identity.getUser(), tableName);
                return privileges.isPresent() && privileges.get().contains(TablePrivilege.SELECT);
            }).findFirst();

            tableRule.ifPresent(rule -> {
                rule.getColumnRegex().ifPresent(pattern -> {
                    List<String> restrictedColumns = columnNames.stream().filter(c -> pattern.matcher(c).matches())
                            .collect(Collectors.toList());
                    if (!restrictedColumns.isEmpty()) {
                        log.warning("denied columns found " + String.join(",", restrictedColumns));
                        AccessDeniedException.denySelectColumns(tableName.getTableName(), restrictedColumns);
                    }
                });
            });
        }
    }

    @Override
    public void checkCanInsertIntoTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, INSERT)) {
            denyInsertTable(tableName.toString());
        }
    }

    @Override
    public void checkCanDeleteFromTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, DELETE)) {
            denyDeleteTable(tableName.toString());
        }
    }

    @Override
    public void checkCanCreateView(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName viewName)
    {
        if (!isDatabaseOwner(identity, viewName.getSchemaName())) {
            denyCreateView(viewName.toString());
        }
    }

    @Override
    public void checkCanDropView(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName viewName)
    {
        if (!checkTablePermission(identity, viewName, OWNERSHIP)) {
            denyDropView(viewName.toString());
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName, Set<String> columnNames)
    {
        // TODO: implement column level permissions
        if (!checkTablePermission(identity, tableName, SELECT)) {
            denySelectTable(tableName.toString());
        }
        if (!checkTablePermission(identity, tableName, GRANT_SELECT)) {
            //denyCreateViewWithSelect(tableName.toString(), identity);
        }
    }

    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, String propertyName)
    {
        if (!canSetSessionProperty(identity, propertyName)) {
            denySetSessionProperty(propertyName);
        }
    }

    @Override
    public void checkCanGrantTablePrivilege(ConnectorTransactionHandle transaction, Identity identity, Privilege privilege, SchemaTableName tableName, String grantee, boolean withGrantOption)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyGrantTablePrivilege(privilege.name(), tableName.toString());
        }
    }

    @Override
    public void checkCanRevokeTablePrivilege(ConnectorTransactionHandle transaction, Identity identity, Privilege privilege, SchemaTableName tableName, String revokee, boolean grantOptionFor)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyRevokeTablePrivilege(privilege.name(), tableName.toString());
        }
    }

    private boolean canSetSessionProperty(Identity identity, String property)
    {
        for (SessionPropertyAccessControlRule rule : sessionPropertyRules) {
            Optional<Boolean> allowed = rule.match(identity.getUser(), property);
            if (allowed.isPresent() && allowed.get()) {
                return true;
            }
            if (allowed.isPresent() && !allowed.get()) {
                return false;
            }
        }
        return false;
    }

    private boolean checkTablePermission(Identity identity, SchemaTableName tableName, TablePrivilege... requiredPrivileges)
    {
        if (INFORMATION_SCHEMA_NAME.equals(tableName.getSchemaName())) {
            return true;
        }

        for (TableWithColumnsAccessControlRule rule : tableRules) {
            Optional<Set<TableWithColumnsAccessControlRule.TablePrivilege>> tablePrivileges = rule.match(identity.getUser(), tableName);
            if (tablePrivileges.isPresent()) {
                return tablePrivileges.get().containsAll(ImmutableSet.copyOf(requiredPrivileges));
            }
        }
        return false;
    }

    private boolean isDatabaseOwner(Identity identity, String schemaName)
    {
        for (SchemaAccessControlRule rule : schemaRules) {
            Optional<Boolean> owner = rule.match(identity.getUser(), schemaName);
            if (owner.isPresent()) {
                return owner.get();
            }
        }
        return false;
    }

    private static void denySetSessionProperty(String propertyName)
    {
        throw new AccessDeniedException("Cannot set catalog session property: " + propertyName);
    }
}
