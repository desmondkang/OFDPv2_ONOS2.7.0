/*
 * Copyright 2022-present Open Networking Foundation
 *
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
package org.onosproject.provider.ofdpv2.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.provider.ofdpv2.impl.OFDPv2Provider;

/**
 * "Troubleshoot OFDPv2 Build Condition"
 */
@Service
@Command(scope = "onos", name = "ofdpv2",
         description = "Troubleshoot OFDPv2 Build Condition")
public class HelloOFDPv2Command extends AbstractShellCommand
{
    @Override
    protected void doExecute() {
        print("Hello %s", "OFDPv2");
        OFDPv2Provider ofdPv2Provider = new OFDPv2Provider();
    }

}
