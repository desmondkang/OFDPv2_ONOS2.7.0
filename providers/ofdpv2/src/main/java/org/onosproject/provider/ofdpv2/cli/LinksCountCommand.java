/*
 * Copyright 2014-present Open Networking Foundation
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

//author: Desmond Kang
package org.onosproject.provider.ofdpv2.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.util.Tools;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.Link;
import org.onosproject.net.link.LinkService;

/**
 * Display Number of Discovered and Active Links
 */
@Service
@Command(scope = "onos", name = "nlinks",
        description = "Display Number of Active Links")
public class LinksCountCommand extends AbstractShellCommand {

    private static final String FMT = "Number of Links Detected: %s links";
    private static final String FMTA = "Number of Active Links Detected: %s links";

    @Override
    protected void doExecute() {
        LinkService service = get(LinkService.class);
        Iterable<Link> links = service.getLinks();
        Iterable<Link> activelinks = service.getActiveLinks();
        if (outputJson()) {
            print("%s", json(this, links));
        } else {
            print(numLink(Tools.stream(links).count()));
            print(numActiveLink(Tools.stream(activelinks).count()));
        }
    }

    /**
     * Produces a JSON array containing the specified links.
     *
     * @param context context to use for looking up codecs
     * @param links collection of links
     * @return JSON array
     */
    public static JsonNode json(AbstractShellCommand context, Iterable<Link> links) {
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode result = mapper.createArrayNode();

        links.forEach(link -> result.add(context.jsonForEntity(link, Link.class)));

        return result;
    }

    /**
     * Produces a JSON object for the specified link.
     *
     * @param context context to use for looking up codecs
     * @param link   link to encode
     * @return JSON object
     */
    public static ObjectNode json(AbstractShellCommand context, Link link) {
        return context.jsonForEntity(link, Link.class);
    }

    /**
     * Returns a formatted string representing the given link.
     *
     * @param numLinks number of links
     * @return formatted link string
     */
    public static String numLink(long numLinks)
    {
        return String.format(FMT, numLinks/2);
    }

    /**
     * Returns a formatted string representing the given link.
     *
     * @param numLinks number of active links
     * @return formatted link string
     */
    public static String numActiveLink(long numLinks)
    {
        return String.format(FMTA, numLinks/2);
    }

}