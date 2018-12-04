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

import io.airlift.configuration.Config;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Null;

public class FileBasedAccessControlWithColumnsConfig
{
    private String configFile;
    private Boolean enableColumnsSecurity = false;
    private Boolean enableLogDecisions = false;

    @NotNull
    public String getConfigFile()
    {
        return configFile;
    }

    @NotNull
    public Boolean isEnableColumnsSecurity() {
        return enableColumnsSecurity;
    }


    @NotNull
    public Boolean isEnableLogDecisions() {
        return this.enableLogDecisions;
    }


    @Config("security.config-file")
    public FileBasedAccessControlWithColumnsConfig setConfigFile(String configFile)
    {
        this.configFile = configFile;
        return this;
    }

    @Config("security.enable-columns-security")
    public FileBasedAccessControlWithColumnsConfig setEnableColumnsSecurity(Boolean enableColumnsSecurity)
    {
        this.enableColumnsSecurity = enableColumnsSecurity;
        return this;
    }

    @Config("security.log-decisions")
    public FileBasedAccessControlWithColumnsConfig setEnableLogDecisions(Boolean enableLogDecisions) {
        this.enableLogDecisions = enableLogDecisions;
        return this;
    }

}