/*******************************************************************************
 * Copyright (c) 2025, 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.mcp.internal;

import static java.security.AccessController.doPrivileged;

import java.lang.reflect.Type;
import java.security.PrivilegedAction;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Spliterator;
import java.util.concurrent.CompletionStage;
import java.util.function.Consumer;
import java.util.function.Function;

import io.openliberty.mcp.internal.schemas.SchemaRegistry;
import io.openliberty.mcp.internal.security.SecurityRequirement;
import io.openliberty.mcp.internal.security.SecurityRequirement.SecurityAnnotation;
import io.openliberty.mcp.tools.ToolManager;
import io.openliberty.mcp.tools.ToolResponse;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.json.JsonObject;
import jakarta.json.bind.Jsonb;

public class ToolRegistry implements ToolManager {

    private static ToolRegistry staticInstance = null;

    public static ToolRegistry get() {
        if (staticInstance != null) {
            return staticInstance;
        }
        return CDI.current().select(McpCdiExtension.class).get().getToolRegistry();
    }

    /**
     * For unit testing only
     *
     * @param toolRegistry the static toolRegistry to set
     */
    public static void set(ToolRegistry toolRegistry) {
        staticInstance = toolRegistry;
    }

    private final SchemaRegistry schemaRegistry;
    private final Jsonb jsonb;

    private final ToolStore toolStore = new ToolStore();

    /**
     * Create a toolRegistry
     *
     * @param schemaRegistry the schema registry to use when generating schemas
     * @param jsonb the jsonb instance to use when converting objects to schemas
     */
    public ToolRegistry(SchemaRegistry schemaRegistry, Jsonb jsonb) {
        this.schemaRegistry = schemaRegistry;
        this.jsonb = jsonb;
    }

    @Override
    public ToolMetadata getTool(String name) {
        ToolMetadata result = toolStore.getTool(name);
        return result;
    }

    /**
     * Add a tool
     *
     * @param tool the tool to add
     * @throws IllegalArgumentException if a tool with the same name already exists
     */
    public void addTool(ToolMetadata tool) {
        toolStore.addTool(tool);
    }

    @Override
    public ToolInfo removeTool(String name) {
        return toolStore.removeTool(name);
    }

    public boolean hasTools() {
        return !toolStore.getAllToolInfos().isEmpty();
    }

    public List<ToolMetadata> getAllTools() {
        return toolStore.getAllToolMetadata();
    }

    @Override
    public Iterator<ToolInfo> iterator() {
        return toolStore.getAllToolInfos().iterator();
    }

    @Override
    public void forEach(Consumer<? super ToolInfo> action) {
        toolStore.getAllToolInfos().forEach(action);
    }

    @Override
    public Spliterator<ToolInfo> spliterator() {
        return toolStore.getAllToolInfos().spliterator();
    }

    @Override
    public ToolDefinition newTool(String name) {
        return new ToolDefinitionImpl(name);
    }

    public class ToolDefinitionImpl implements ToolDefinition {

        private final String name;
        private String title;
        private String description;
        private final List<ToolArgument> arguments = new ArrayList<>();
        private Class<?> outputClass;
        private Object inputSchema;
        private Object outputSchema;
        private Function<ToolArguments, ToolResponse> handler;
        private Function<ToolArguments, CompletionStage<ToolResponse>> asyncHandler;
        private Optional<ToolAnnotations> toolAnnotations = Optional.empty();

        public ToolDefinitionImpl(String name) {
            this.name = name;
        }

        @Override
        public ToolDefinition setDescription(String description) {
            this.description = description;
            return this;
        }

        @Override
        public ToolDefinition setHandler(Function<ToolArguments, ToolResponse> fun) {
            this.handler = fun;
            return this;
        }

        @Override
        public ToolDefinition setAsyncHandler(Function<ToolArguments, CompletionStage<ToolResponse>> fun) {
            this.asyncHandler = fun;
            return this;
        }

        @Override
        public ToolDefinition addArgument(String name, String description, boolean required, Type type) {
            ToolArgument arg = new ToolArgument(name, description, required, type, null);
            arguments.add(arg);
            return this;
        }

        @Override
        public ToolDefinition addArgument(String name, String description, boolean required, Type type, String defaultValue) {
            ToolArgument arg = new ToolArgument(name, description, required, type, defaultValue);
            arguments.add(arg);
            return this;
        }

        @Override
        public ToolDefinition setAnnotations(ToolAnnotations annotations) {
            toolAnnotations = Optional.ofNullable(annotations);
            return this;
        }

        @Override
        public ToolDefinition setTitle(String title) {
            this.title = title;
            return this;
        }

        @Override
        public ToolDefinition generateOutputSchema(Class<?> from) {
            outputClass = from;
            return this;
        }

        @Override
        public ToolDefinition setOutputSchema(Object schema) {
            outputSchema = schema;
            return this;
        }

        @Override
        public ToolDefinition setInputSchema(Object schema) {
            inputSchema = schema;
            return this;
        }

        @Override
        public ToolInfo register() {
            boolean isAsync = asyncHandler != null;
            if (isAsync && handler != null) {
                throw new RuntimeException("Cannot set both handler and asyncHandler");
            } else if (!isAsync && handler == null) {
                throw new RuntimeException("One of handler or asyncHandler must be set");
            }

            JsonObject inputSchema = getInputSchema(this.inputSchema, arguments);
            JsonObject outputSchema = getOutputSchema(this.outputSchema, outputClass);

            SecurityRequirement securityRequirement = new SecurityRequirement(SecurityAnnotation.NONE, Collections.emptyList());

            ToolMetadata newTool = new ToolMetadata(name,
                                                    title,
                                                    description,
                                                    arguments,
                                                    toolAnnotations,
                                                    isAsync,
                                                    inputSchema,
                                                    outputSchema,
                                                    handler,
                                                    asyncHandler,
                                                    Optional.empty(), // Method metadata
                                                    securityRequirement,
                                                    Instant.now());

            addTool(newTool);

            return newTool;
        }

        /**
         * Creates an outputSchema based on the information provided by the user.
         * <p>
         * Uses {@code outputSchema} if provided, otherwise generates a schema from {@code outputClass} if provided, otherwise returns {@code null}
         * <p>
         * {@code outputSchema} will be returned if it is a {@code JsonObject}, otherwise it will be converted using JSON-B
         *
         * @param outputSchema an object representing a literal JSON schema, may be {@code null}
         * @param outputClass the tool return type, may be {@code null}
         * @return the parsed schema created from {@code outputSchema} or {@code outputClass}, or {@code null}
         */
        private JsonObject getOutputSchema(Object outputSchema, Class<?> outputClass) {
            if (outputSchema != null) {
                return convertToJsonObject(outputSchema);
            } else if (outputClass != null) {
                // doPrivileged required because this needs to do reflection
                return doPrivileged((PrivilegedAction<JsonObject>) () -> schemaRegistry.getToolOutputSchema(null, outputClass));
            } else {
                return null;
            }
        }

        /**
         * Creates an inputSchema based on the information provided by the user.
         * <p>
         * Uses {@code inputSchema} if provided, otherwise generates a schema from the tool arguments.
         * <p>
         * {@code inputSchema} will be returned if it is a {@code JsonObject}, otherwise it will be converted using JSON-B
         *
         * @param inputSchema an object representing a literal JSON schema, may be {@code null}
         * @param arguments the list of tool arguments
         * @return the parsed {@code inputSchema} if not {@code null}, or the input schema generated from {@code arguments}
         */
        private JsonObject getInputSchema(Object inputSchema, List<ToolArgument> arguments) {
            if (inputSchema != null) {
                return convertToJsonObject(inputSchema);
            } else {
                // doPrivileged required because this needs to do reflection
                return doPrivileged((PrivilegedAction<JsonObject>) () -> schemaRegistry.getProgrammaticToolInputSchema(arguments));
            }
        }

        private JsonObject convertToJsonObject(Object schema) {
            if (schema instanceof JsonObject jsonSchema) {
                return jsonSchema;
            } else {
                String json = jsonb.toJson(schema);
                return jsonb.fromJson(json, JsonObject.class);
            }
        }
    }

}
