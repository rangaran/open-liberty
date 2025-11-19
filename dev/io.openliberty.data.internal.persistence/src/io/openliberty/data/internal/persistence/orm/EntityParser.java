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

import static io.openliberty.data.internal.persistence.cdi.DataExtension.exc;

import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import io.openliberty.data.internal.persistence.Util;
import io.openliberty.data.internal.persistence.orm.Models.AccessType;
import io.openliberty.data.internal.persistence.orm.Models.Attribute;
import io.openliberty.data.internal.persistence.orm.Models.AttributeKind;
import io.openliberty.data.internal.persistence.orm.Models.Converter;
import io.openliberty.data.internal.persistence.orm.Models.EmbeddableRecord;
import io.openliberty.data.internal.persistence.orm.Models.EntityRecord;
import io.openliberty.data.internal.persistence.orm.Models.IncompleteAttribute;
import io.openliberty.data.internal.persistence.orm.Models.MappedSuperclass;
import jakarta.data.exceptions.MappingException;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Convert;

/**
 * TODO javadoc and trace
 */
public class EntityParser {

    // State of the parser
    private enum STATE {
        INIT, PARSING, GENERATING
    };

    // ORM sets
    private final SortedSet<MappedSuperclass> mappedSuperclasses;
    private final SortedSet<EntityRecord> entities;
    private final SortedSet<EmbeddableRecord> embeddables;
    private final SortedSet<Converter> converters;

    // Convertible classes
    private final Set<Class<?>> convertibles;

    // Relationships
    private final Relationships relate;

    // Global configurations
    private final String tablePrefix;

    // State controls flow from initialization to generation
    private final AtomicReference<STATE> state;

    // Current entity being parsed
    private Class<?> currentEntity;
    private Set<Attribute> idAttributes;

    public EntityParser(String tablePrefix) {
        this.mappedSuperclasses = new TreeSet<>();
        this.entities = new TreeSet<>();
        this.embeddables = new TreeSet<>();
        this.converters = new TreeSet<>();
        this.convertibles = new HashSet<>();
        this.relate = new Relationships();
        this.tablePrefix = tablePrefix;
        this.state = new AtomicReference<>(STATE.INIT);
    }

    public void parseAnnotatedEntity(Class<?> annotatedEntity) {
        state.compareAndSet(STATE.INIT, STATE.PARSING);
        if (state.get() != STATE.PARSING) {
            // Internal exception
            throw new IllegalStateException("Attempted to parse an entity while EntityParser was in state: " + state.get());
        }

        AnnotatedUtilities.findConvertersInEntity(annotatedEntity, converters);
    }

    public void parseRecord(Class<?> record, Class<?> generatedEntity) {
        state.compareAndSet(STATE.INIT, STATE.PARSING);
        if (state.get() != STATE.PARSING) {
            // Internal exception
            throw new IllegalStateException("Attempted to parse an entity while EntityParser was in state: " + state.get());
        }

        relate.entityToRecord(generatedEntity, record);

        parse(generatedEntity, tablePrefix + record.getSimpleName());
    }

    public void parseUnannotatedEntity(Class<?> entity) {
        state.compareAndSet(STATE.INIT, STATE.PARSING);
        if (state.get() != STATE.PARSING) {
            // Internal exception
            throw new IllegalStateException("Attempted to parse an entity while EntityParser was in state: " + state.get());
        }

        parse(entity, tablePrefix + entity.getSimpleName());

    }

    private void parse(Class<?> entity, String tableName) {
        state.compareAndSet(STATE.INIT, STATE.PARSING);
        if (state.get() != STATE.PARSING) {
            // Internal exception
            throw new IllegalStateException("Attempted to parse an entity while EntityParser was in state: " + state.get());
        }

        // If entity was unannotated then we must
        // construct an object relational mapping
        this.currentEntity = entity;
        this.idAttributes = new HashSet<>();

        for (Class<?> superclass = currentEntity; //
                        superclass != null && superclass != Object.class; //
                        superclass = superclass.getSuperclass()) {

            for (Convert convert : superclass.getAnnotationsByType(Convert.class)) {
                recordConverter(convert);
            }

            if (superclass == currentEntity) {
                // Record entity and any embeddables found along the way
                entities.add(new EntityRecord(superclass, tableName, finalizeAttributes(superclass, findAttributes(superclass))));
                continue;
            }

            // Record all mapped superclasses and any embeddables found along the way
            relate.entityToMappedSuperclass(currentEntity, superclass);
            mappedSuperclasses.add(new MappedSuperclass(superclass, finalizeAttributes(superclass, findAttributes(superclass))));
        }

        verify();
    }

    private Set<IncompleteAttribute> findAttributes(Class<?> c) {
        SortedSet<IncompleteAttribute> attributes = new TreeSet<>();

        if (relate.entityHasRecord(c)) {
            Class<?> r = relate.recordForEntity(c);
            for (RecordComponent rc : r.getRecordComponents())
                attributes.add(new IncompleteAttribute(rc.getType(), rc.getName(), AccessType.FIELD));
        } else {
            for (Field f : c.getDeclaredFields()) {
                if (Modifier.isPublic(f.getModifiers())) {
                    attributes.add(new IncompleteAttribute(f.getType(), f.getName(), AccessType.FIELD));

                    for (Convert convert : f.getAnnotationsByType(Convert.class))
                        recordConverter(convert);
                }
            }

            try {
                PropertyDescriptor[] propertyDescriptors = Introspector //
                                .getBeanInfo(c).getPropertyDescriptors();
                if (propertyDescriptors != null)
                    for (PropertyDescriptor p : propertyDescriptors) {
                        if (p.getWriteMethod() != null) {
                            //Note: p.getName() utilizes Introspector.decapitalize method
                            //      which honors acryonyms like getURL/setURL -> URL (instead of uRL)
                            attributes.add(new IncompleteAttribute(p.getPropertyType(), p.getName(), AccessType.PROPERTY));
                        }

                        if (p.getReadMethod() != null)
                            for (Convert convert : p.getReadMethod().getAnnotationsByType(Convert.class))
                                recordConverter(convert);
                    }

            } catch (IntrospectionException x) {
                throw new MappingException(x);
            }
        }
        return attributes;
    }

    private Set<Attribute> finalizeAttributes(Class<?> c, Set<IncompleteAttribute> incompletes) {
        SortedSet<Attribute> attributes = new TreeSet<>();

        IncompleteAttribute id = null;
        IncompleteAttribute version = null;

        // Determine which attribute is the id and version (optional).
        // Id precedence:
        // (1) name is id, ignoring case.
        // (2) name ends with _id, ignoring case.
        // (3) name ends with Id or ID.
        // (4) type is UUID.
        // Version precedence (if also a valid version type):
        // (1) name is version, ignoring case.
        // (2) name is _version, ignoring case.
        int idPrecedence = 10;
        int vPrecedence = 10;
        for (IncompleteAttribute attr : incompletes) {
            String name = attr.name();
            Class<?> type = attr.type();
            int len = name.length();

            if (idPrecedence > 1 &&
                len >= 2 &&
                name.regionMatches(true, len - 2, "id", 0, 2)) {
                if (name.length() == 2) {
                    id = attr;
                    idPrecedence = 1;
                } else if (idPrecedence > 2 &&
                           name.charAt(len - 3) == '_') {
                    id = attr;
                    idPrecedence = 2;
                } else if (idPrecedence > 3 &&
                           name.charAt(len - 2) == 'I') {
                    id = attr;
                    idPrecedence = 3;
                }
            } else if (idPrecedence > 4 && UUID.class.equals(type)) {
                id = attr;
                idPrecedence = 4;
            }

            if (vPrecedence > 1 &&
                len == 7 &&
                Util.VERSION_TYPES.contains(type) &&
                "version".equalsIgnoreCase(name)) {
                version = attr;
                vPrecedence = 1;
            } else if (vPrecedence > 2 &&
                       len == 8 &&
                       Util.VERSION_TYPES.contains(type) &&
                       "_version".equalsIgnoreCase(name)) {
                version = attr;
                vPrecedence = 2;
            }
        }

        for (IncompleteAttribute attr : incompletes) {
            Class<?> type = attr.type();

            boolean isId = attr == id;
            boolean isVersion = attr == version;
            boolean isPrimitive = type.isPrimitive();
            boolean isCollection = Collection.class.isAssignableFrom(type);

            AttributeKind kind;
            if (isPrimitive || type.isInterface() || //
                Serializable.class.isAssignableFrom(type)) {
                if (isId)
                    kind = AttributeKind.ID;
                else if (isCollection)
                    kind = AttributeKind.ELEMENT_COLLECTION;
                else if (isVersion)
                    kind = AttributeKind.VERSION;
                else
                    kind = AttributeKind.BASIC;
            } else {
                if (isId)
                    kind = AttributeKind.EMBEDDED_ID;
                else
                    kind = AttributeKind.EMBEDDED;
            }

            Attribute finalized;

            if (kind == AttributeKind.EMBEDDED || kind == AttributeKind.EMBEDDED_ID) {
                Set<Attribute> embedAttributes = finalizeAttributes(c, findAttributes(type));

                finalized = new Attribute(attr, kind, embedAttributes);
                attributes.add(finalized);

                embeddables.add(new EmbeddableRecord(type, embedAttributes));

                relate.entityToEmbed(c, type);
            } else {
                finalized = new Attribute(attr, kind, Set.of());
                attributes.add(finalized);
            }

            // Found id attribute, record it for verification and witness any overwritten ids
            if (finalized.isId()) {
                idAttributes.add(finalized);
            }
        }

        return attributes;
    }

    private void recordConverter(Convert convert) {
        if (convert.converter() != null && convert.converter() != AttributeConverter.class) {
            Class<?> converterType = convert.converter();

            for (Class<?> c = converterType; c != null; c = c.getSuperclass())
                for (Type ifc : c.getGenericInterfaces())
                    if (ifc instanceof ParameterizedType type &&
                        ifc.getTypeName().startsWith(Util.ATTR_CONVERTER_CLASS_NAME)) {
                        Type[] typeParams = type.getActualTypeArguments();
                        if (Util.UNSUPPORTED_ATTR_TYPES.contains(typeParams[1]))
                            throw exc(MappingException.class,
                                      "CWWKD1111.unsupported.convert",
                                      converterType.getName(),
                                      typeParams[0].getTypeName(),
                                      typeParams[1].getTypeName(),
                                      Util.SUPPORTED_TEMPORAL_TYPES,
                                      Util.SUPPORTED_BASIC_TYPES);

                        if (typeParams[0] instanceof Class)
                            convertibles.add((Class<?>) typeParams[0]);
                    }
            converters.add(new Converter(convert.converter()));
        }
    }

    private void verify() {
        if (idAttributes.isEmpty()) {
            // Costly operations, only do for error state
            EntityRecord invalid = entities.stream()//
                            .filter(e -> e.type() == currentEntity)//
                            .findFirst()//
                            .orElseThrow();
            Set<Class<?>> supers = relate.superclassesForEntity(currentEntity);
            Set<MappedSuperclass> invalidSupers = supers.isEmpty() ? Set.of() : mappedSuperclasses.stream()//
                            .filter(e -> supers.contains(e.type()))//
                            .collect(Collectors.toSet());

            //TODO NLS
            throw new MappingException("The entity " + invalid + " had no id attribute"
                                       + (invalidSupers.isEmpty() ? " " : " nor was any id attribute found on any mapped superclass " + invalidSupers));
        }

        if (idAttributes.size() > 1) {
            // Costly operations, only do for error state
            EntityRecord invalid = entities.stream()//
                            .filter(e -> e.type() == currentEntity)//
                            .findFirst()//
                            .orElseThrow();
            Set<Class<?>> supers = relate.superclassesForEntity(currentEntity);
            Set<MappedSuperclass> invalidSupers = supers.isEmpty() ? Set.of() : mappedSuperclasses.stream()//
                            .filter(e -> supers.contains(e.type()))//
                            .collect(Collectors.toSet());

            //TODO NLS
            throw new MappingException("The entity " + invalid + " had more than one id attribute due to a combination of the entity's own attributes"
                                       + " and the attributes of the entity's mapped superclasses " + invalidSupers + ". "
                                       + "The id attributes are: " + idAttributes);
        }
    }

    public List<String> generateView() {
        state.compareAndSet(STATE.PARSING, STATE.GENERATING);
        if (state.get() != STATE.GENERATING) {
            // Internal exception
            throw new IllegalStateException("Attempted to generate EntityParser view while EntityParser was in state: " + state.get());
        }

        View view = new View(mappedSuperclasses.size() + entities.size() + embeddables.size() + converters.size());

        for (MappedSuperclass sc : mappedSuperclasses) {
            view.mappedSuperclass(sc);
        }

        for (EntityRecord er : entities) {
            view.entity(er);
        }

        for (EmbeddableRecord emb : embeddables) {
            view.embedable(emb);
        }

        for (Converter con : converters) {
            view.converter(con);
        }

        return view.get();
    }

    public Set<Class<?>> getConvertibiles() {
        state.compareAndSet(STATE.PARSING, STATE.GENERATING);
        if (state.get() != STATE.GENERATING) {
            // Internal exception
            throw new IllegalStateException("Attempted to generate EntityParser view while EntityParser was in state: " + state.get());
        }
        return convertibles;
    }
}
