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
package com.facebook.presto.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.airlift.log.Logger;

import java.util.Optional;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public class CatalogAccessControlRule
{
    private final boolean allow;
    private final Optional<Pattern> userRegex;
    private final Optional<Pattern> catalogRegex;
    private final Optional<Pattern> schemaRegex;
    private final Optional<Pattern> tableRegex;
    private final Optional<Pattern> columnRegex;

    private static final Logger log = Logger.get(CatalogAccessControlRule.class);

    @JsonCreator
    public CatalogAccessControlRule(
            @JsonProperty("allow") boolean allow,
            @JsonProperty("user") Optional<Pattern> userRegex,
            @JsonProperty("catalog") Optional<Pattern> catalogRegex,
            @JsonProperty("schema") Optional<Pattern> schemaRegex,
            @JsonProperty("table") Optional<Pattern> tableRegex,
            @JsonProperty("restricted_columns") Optional<Pattern> columnRegex)
    {
        this.allow = allow;
        this.userRegex = requireNonNull(userRegex, "userRegex is null");
        this.catalogRegex = requireNonNull(catalogRegex, "catalogRegex is null");
        this.schemaRegex = requireNonNull(schemaRegex, "schema is null");
        this.tableRegex = requireNonNull(tableRegex, "table is null");
        this.columnRegex = requireNonNull(columnRegex, "column list is null");
    }

    public Optional<Boolean> match(String user, String catalog)
    {
        if (userRegex.map(regex -> regex.matcher(user).matches()).orElse(true) &&
                catalogRegex.map(regex -> regex.matcher(catalog).matches()).orElse(true)) {
            return Optional.of(allow);
        }
        return Optional.empty();
    }

    public Optional<Boolean> matchSchema(String user, String schema)
    {
        if (userRegex.map(regex -> regex.matcher(user).matches()).orElse(true) &&
                schemaRegex.map(regex -> regex.matcher(schema).matches()).orElse(true)) {
            return Optional.of(allow);
        }
        return Optional.empty();
    }

    public Optional<Boolean> matchTable(String user, String table)
    {
        if (userRegex.map(regex -> regex.matcher(user).matches()).orElse(true) &&
                tableRegex.map(regex -> regex.matcher(table).matches()).orElse(true)) {
            return Optional.of(allow);
        }
        return Optional.empty();
    }

    public Optional<Pattern> getColumnRegex()
    {
        return columnRegex;
    }
}
