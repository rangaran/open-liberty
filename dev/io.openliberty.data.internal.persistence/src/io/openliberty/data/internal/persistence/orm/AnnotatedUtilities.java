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

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.SortedSet;

import io.openliberty.data.internal.persistence.orm.Models.Converter;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.EmbeddedId;

/**
 *
 */
public class AnnotatedUtilities {

    //TODO find unannotated entities indirectly referenced via relationships

    public static void findConvertersInEntity(Class<?> entity, SortedSet<Converter> converters) {
        for (Class<?> superclass = entity; //
                        superclass != null && superclass != Object.class; //
                        superclass = superclass.getSuperclass()) {
            findConverters(superclass, converters);
        }
    }

    private static void findConverters(Class<?> c, SortedSet<Converter> converters) {
        for (Convert convert : c.getAnnotationsByType(Convert.class))
            if (convert.converter() != null && convert.converter() != AttributeConverter.class)
                converters.add(new Converter(convert.converter()));

        for (Field f : c.getDeclaredFields()) {
            forEmbeddable(f).ifPresent(emb -> findConverters(emb, converters));
            for (Convert convert : f.getAnnotationsByType(Convert.class))
                if (convert.converter() != null && convert.converter() != AttributeConverter.class)
                    converters.add(new Converter(convert.converter()));
        }

        for (Method m : c.getDeclaredMethods()) {
            forEmbeddable(m).ifPresent(emb -> findConverters(emb, converters));
            for (Convert convert : m.getAnnotationsByType(Convert.class))
                if (convert.converter() != null && convert.converter() != AttributeConverter.class)
                    converters.add(new Converter(convert.converter()));
        }

    }

    private static Optional<Class<?>> forEmbeddable(Field f) {
        if (f.isAnnotationPresent(Embedded.class) ||
            f.isAnnotationPresent(EmbeddedId.class)) {
            if (f.getType().isAnnotationPresent(Embeddable.class)) {
                return Optional.of(f.getType());
            }
        }
        return Optional.empty();
    }

    private static Optional<Class<?>> forEmbeddable(Method m) {
        if (m.isAnnotationPresent(Embedded.class) ||
            m.isAnnotationPresent(EmbeddedId.class)) {
            if (m.getReturnType().isAnnotationPresent(Embeddable.class)) {
                return Optional.of(m.getReturnType());
            }
        }
        return Optional.empty();
    }

}
