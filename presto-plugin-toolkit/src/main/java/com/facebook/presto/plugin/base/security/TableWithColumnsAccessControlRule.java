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

import com.facebook.presto.spi.SchemaTableName;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableSet;

import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public class TableWithColumnsAccessControlRule
{
    private final Set<TablePrivilege> privileges;
    private final Optional<Pattern> userRegex;
    private final Optional<Pattern> schemaRegex;
    private final Optional<Pattern> tableRegex;
    private final Optional<Pattern> columnRegex;

    @JsonCreator
    public TableWithColumnsAccessControlRule(
            @JsonProperty("privileges") Set<TablePrivilege> privileges,
            @JsonProperty("user") Optional<Pattern> userRegex,
            @JsonProperty("schema") Optional<Pattern> schemaRegex,
            @JsonProperty("table") Optional<Pattern> tableRegex,
            @JsonProperty("restricted_columns") Optional<Pattern> columnRegex
            )
    {
        this.privileges = ImmutableSet.copyOf(requireNonNull(privileges, "privileges is null"));
        this.userRegex = requireNonNull(userRegex, "userRegex is null");
        this.schemaRegex = requireNonNull(schemaRegex, "sourceRegex is null");
        this.tableRegex = requireNonNull(tableRegex, "tableRegex is null");
        this.columnRegex = requireNonNull(columnRegex, "columnRegex is null");
    }

    public Optional<Set<TablePrivilege>> match(String user, SchemaTableName table)
    {
        if (userRegex.map(regex -> regex.matcher(user).matches()).orElse(true) &&
                schemaRegex.map(regex -> regex.matcher(table.getSchemaName()).matches()).orElse(true) &&
                tableRegex.map(regex -> regex.matcher(table.getTableName()).matches()).orElse(true)) {
            return Optional.of(privileges);
        }
        return Optional.empty();
    }


    public Optional<Pattern> getColumnRegex()
    {
        return columnRegex;
    }

    public Optional<Pattern> getSchemaRegex() {
        return schemaRegex;
    }

    public Optional<Pattern> getTableRegex() {
        return tableRegex;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("user=").append(userRegex.orElse(null))
                .append(", schema=")
                .append(schemaRegex.orElse(null))
                .append(", table=").append(tableRegex.orElse(null))
        .append(", columns=").append(columnRegex.orElse(null));
        return builder.toString();
    }

    public enum TablePrivilege
    {
        SELECT, INSERT, DELETE, OWNERSHIP, GRANT_SELECT
    }
}
