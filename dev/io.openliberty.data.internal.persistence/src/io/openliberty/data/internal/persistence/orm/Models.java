/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.data.internal.persistence.orm;

import java.util.Set;

import com.ibm.websphere.ras.annotation.Trivial;

@Trivial
public class Models {
    enum AccessType {
        FIELD, PROPERTY;
    }

    enum AttributeKind {
        ID, EMBEDDED_ID, BASIC, VERSION, ELEMENT_COLLECTION, EMBEDDED;

        public String toElementName() {
            return this.name().toLowerCase().replace('_', '-');
        }
    }

    static record IncompleteAttribute(Class<?> type, String name, AccessType access)
                    implements Comparable<IncompleteAttribute> {

        @Override
        public int compareTo(IncompleteAttribute o) {
            return this.name.compareTo(o.name);
        }
    }

    static record Attribute(IncompleteAttribute incomplete, AttributeKind kind, Set<Attribute> overrides)
                    implements Comparable<Attribute> {

        public Class<?> type() {
            return incomplete.type();
        }

        public String name() {
            return incomplete.name();
        }

        public AccessType access() {
            return incomplete.access();
        }

        public boolean isCollection() {
            return this.kind() == AttributeKind.ELEMENT_COLLECTION;
        }

        public boolean isId() {
            return this.kind == AttributeKind.EMBEDDED_ID || this.kind == AttributeKind.ID;
        }

        public boolean rejectsNull() {
            return this.type().isPrimitive() && this.kind != AttributeKind.EMBEDDED;
        }

        @Override
        public int compareTo(Attribute o) {
            if (this.kind == o.kind) {
                return this.incomplete.compareTo(o.incomplete);
            }

            return Integer.compare(this.kind.ordinal(), o.kind.ordinal());
        }
    }

    static record MappedSuperclass(Class<?> type, Set<Attribute> attributes)
                    implements Comparable<MappedSuperclass> {

        @Override
        public int compareTo(MappedSuperclass o) {
            return this.type.getName().compareTo(o.type.getName());
        }
    }

    static record EntityRecord(Class<?> type, String tableName, Set<Attribute> attributes)
                    implements Comparable<EntityRecord> {

        @Override
        public int compareTo(EntityRecord o) {
            return this.type.getName().compareTo(o.type.getName());
        }
    }

    static record EmbeddableRecord(Class<?> type, Set<Attribute> attributes)
                    implements Comparable<EmbeddableRecord> {

        @Override
        public int compareTo(EmbeddableRecord o) {
            return this.type.getName().compareTo(o.type.getName());
        }
    }

    static record Converter(Class<?> type) implements Comparable<Converter> {

        @Override
        public int compareTo(Converter o) {
            return this.type.getName().compareTo(o.type.getName());
        }

    }
}
