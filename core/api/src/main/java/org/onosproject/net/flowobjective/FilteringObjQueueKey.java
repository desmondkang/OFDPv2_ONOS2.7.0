/*
 * Copyright 2018-present Open Networking Foundation
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

package org.onosproject.net.flowobjective;

import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.criteria.Criterion;

import java.util.Objects;

/**
 * Filtering objective queue key.
 */
public class FilteringObjQueueKey implements ObjectiveQueueKey {
    private DeviceId deviceId;
    private int priority;
    private Criterion key;

    public FilteringObjQueueKey(DeviceId deviceId, int priority, Criterion key) {
        this.deviceId = deviceId;
        this.priority = priority;
        this.key = key;
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceId, priority, key);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof FilteringObjQueueKey)) {
            return false;
        }
        FilteringObjQueueKey that = (FilteringObjQueueKey) other;
        return Objects.equals(this.deviceId, that.deviceId) &&
                Objects.equals(this.priority, that.priority) &&
                Objects.equals(this.key, that.key);
    }
}