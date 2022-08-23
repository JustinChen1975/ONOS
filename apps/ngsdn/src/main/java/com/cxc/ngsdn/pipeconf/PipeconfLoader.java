/*
 * Copyright 2019-present Open Networking Foundation
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

//  这个文件是必须的，是进入点。

package com.cxc.ngsdn.pipeconf;

import com.cxc.ngsdn.api.IntProgrammable;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.driver.DriverAdminService;
import org.onosproject.net.driver.DriverProvider;
import org.onosproject.net.pi.model.DefaultPiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
//import org.onosproject.pipelines.basic.IntProgrammableImpl;
//import org.onosproject.pipelines.basic.IntProgrammableImpl;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;

import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.BMV2_JSON;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.P4_INFO_TEXT;
//  pipeconf_id被取名为 com.cxc.ngsdn
import static com.cxc.ngsdn.AppConstants.PIPECONF_ID;

/**
 * Component that builds and register the pipeconf at app activation.
 */
@Component(immediate = true, service = PipeconfLoader.class)
public final class PipeconfLoader {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String P4INFO_PATH = "/p4info.txt";
    private static final String BMV2_JSON_PATH = "/bmv2.json";

    // 當 ONOS 啟動 PipeconfLoader 時，會透過 PiPipeconfService 去註冊 Pipeconf
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DriverAdminService driverAdminService;

    @Activate
    public void activate() {
        // Registers the pipeconf at component activation.
        if (pipeconfService.getPipeconf(PIPECONF_ID).isPresent()) {
            // Remove first if already registered, to support reloading of the
            // pipeconf during the tutorial.
            pipeconfService.unregister(PIPECONF_ID);
        }
        removePipeconfDrivers();
        try {
            pipeconfService.register(buildPipeconf());
        } catch (P4InfoParserException e) {
            log.error("Unable to register " + PIPECONF_ID, e);
        }
    }

    @Deactivate
    public void deactivate() {
        // Do nothing.
    }

    private PiPipeconf buildPipeconf() throws P4InfoParserException {

		/*
		就是你想获得文件，你得从最终生成的.class文件为着手点，不要以.java文件的路径为出发点，因为真正使用的就是.class，不会拿个.java文件就使用，因为java是编译型语言嘛
		至于getResouce()方法的参数，你以class为出发点，再结合相对路径的概念，就可以准确地定位资源文件了，至于它的根目录嘛，你用不同的IDE build出来是不同的位置下的，不过都是以顶层package作为根目录，比如在Web应用中，有一个WEB-INF的目录，WEB-INF目录里面除了web.xml文件外，还有一个classes目录，没错了，它就是你这个WEB应用的package的顶层目录，也是所有.class的根目录“/”，假如clasaes目录下面有一个file.txt文件，它的相对路径就是"/file.txt"，如果相对路径不是以"/"开头，那么它就是相对于.class的路径。。
		来自 <https://www.cnblogs.com/hfultrastrong/p/9279371.html> 
        */

        final URL p4InfoUrl = PipeconfLoader.class.getResource(P4INFO_PATH);
        final URL bmv2JsonUrlUrl = PipeconfLoader.class.getResource(BMV2_JSON_PATH);
        final PiPipelineModel pipelineModel = P4InfoParser.parse(p4InfoUrl);

        return DefaultPiPipeconf.builder()
                .withId(PIPECONF_ID)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, InterpreterImpl.class)
                .addBehaviour(Pipeliner.class, PipelinerImpl.class)
//                .addBehaviour(IntProgrammable.class, IntProgrammableImpl.class)
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(BMV2_JSON, bmv2JsonUrlUrl)
                .build();
    }

	//看起来ONOS对INT有原生的支持。
                // .addBehaviour(IntProgrammable.class, IntProgrammableImpl.class)

    private void removePipeconfDrivers() {
        List<DriverProvider> driverProvidersToRemove = driverAdminService
                .getProviders().stream()
                .filter(p -> p.getDrivers().stream()
                        .anyMatch(d -> d.name().endsWith(PIPECONF_ID.id())))
                .collect(Collectors.toList());

        if (driverProvidersToRemove.isEmpty()) {
            return;
        }

        log.info("Found {} outdated drivers for pipeconf '{}', removing...",
                 driverProvidersToRemove.size(), PIPECONF_ID);

        driverProvidersToRemove.forEach(driverAdminService::unregisterProvider);
    }
}
