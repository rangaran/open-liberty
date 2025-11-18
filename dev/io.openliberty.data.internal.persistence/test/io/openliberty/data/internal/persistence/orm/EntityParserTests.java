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

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

/**
 * TODO test an element collection of embeddables
 * TODO test an annotated entity
 */
public class EntityParserTests {

    @Test
    public void simpleEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(Simple.class);
        List<String> xmls = p.generateView();

        assertEquals(1, xmls.size());

        final String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.Simple">
                            <table name="Simple"/>
                            <attributes>
                              <id name="id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="FIELD">
                              </basic>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(0));
    }

    @Test
    public void simpleEntityWithPrefixTest() {
        EntityParser p = new EntityParser("prefix");
        p.parse(Simple.class);
        List<String> xmls = p.generateView();

        assertEquals(1, xmls.size());

        final String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.Simple">
                            <table name="prefixSimple"/>
                            <attributes>
                              <id name="id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="FIELD">
                              </basic>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(0));
    }

    @Test
    public void versionedEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(Versioned.class);
        List<String> xmls = p.generateView();

        assertEquals(1, xmls.size());

        final String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.Versioned">
                            <table name="Versioned"/>
                            <attributes>
                              <id name="identifier" access="FIELD">
                              </id>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="FIELD">
                              </basic>
                              <version name="version" access="FIELD">
                              </version>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(0));
    }

    @Test
    public void collectionEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(Collection.class);
        List<String> xmls = p.generateView();

        assertEquals(1, xmls.size());

        final String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.Collection">
                            <table name="Collection"/>
                            <attributes>
                              <id name="collectionId" access="FIELD">
                                <column nullable="false"/>
                              </id>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="FIELD">
                              </basic>
                              <element-collection name="friends" access="FIELD" fetch="EAGER">
                              </element-collection>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(0));
    }

    @Test
    public void propertyEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(Property.class);
        List<String> xmls = p.generateView();

        assertEquals(1, xmls.size());

        final String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.Property">
                            <table name="Property"/>
                            <attributes>
                              <id name="prop_id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                              <basic name="URL" access="PROPERTY">
                              </basic>
                              <basic name="email" access="PROPERTY">
                              </basic>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="FIELD">
                              </basic>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(0));
    }

    @Test
    public void embeddedEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(WithEmbedded.class);
        List<String> xmls = p.generateView();

        assertEquals(2, xmls.size());

        String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.WithEmbedded">
                            <table name="WithEmbedded"/>
                            <attributes>
                              <id name="id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                              <embedded name="name" access="FIELD">
                                <attribute-override name="firstName">
                                  <column name="NAME_FIRSTNAME"/>
                                </attribute-override>
                                <attribute-override name="lastName">
                                  <column name="NAME_LASTNAME"/>
                                </attribute-override>
                              </embedded>
                            </attributes>
                          </entity>
                        """;
        assertEquals(expected, xmls.get(0));

        expected = """
                          <embeddable class="io.openliberty.data.internal.persistence.orm.WithEmbedded$Name">
                            <attributes>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="FIELD">
                              </basic>
                            </attributes>
                          </embeddable>
                        """;
        assertEquals(expected, xmls.get(1));
    }

    @Test
    public void embeddedIdEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(WithEmbeddedId.class);
        List<String> xmls = p.generateView();

        assertEquals(2, xmls.size());

        String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.WithEmbeddedId">
                            <table name="WithEmbeddedId"/>
                            <attributes>
                              <embedded-id name="name_id" access="FIELD">
                                <attribute-override name="firstName">
                                  <column name="NAME_ID_FIRSTNAME"/>
                                </attribute-override>
                                <attribute-override name="lastName">
                                  <column name="NAME_ID_LASTNAME"/>
                                </attribute-override>
                              </embedded-id>
                              <version name="version" access="FIELD">
                              </version>
                            </attributes>
                          </entity>
                        """;
        assertEquals(expected, xmls.get(0));

        expected = """
                          <embeddable class="io.openliberty.data.internal.persistence.orm.WithEmbeddedId$Name">
                            <attributes>
                              <basic name="firstName" access="PROPERTY">
                              </basic>
                              <basic name="lastName" access="PROPERTY">
                              </basic>
                            </attributes>
                          </embeddable>
                        """;
        assertEquals(expected, xmls.get(1));
    }

    @Test
    public void mappedSuperClassEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(WithMappedSuperclass.class);
        List<String> xmls = p.generateView();

        assertEquals(5, xmls.size());

        String expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.SuperAlpha">
                            <attributes>
                              <version name="version" access="FIELD">
                              </version>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(0));

        expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.SuperBeta">
                            <attributes>
                              <embedded name="script" access="FIELD">
                                <attribute-override name="lowercase">
                                  <column name="SCRIPT_LOWERCASE"/>
                                </attribute-override>
                                <attribute-override name="uppercase">
                                  <column name="SCRIPT_UPPERCASE"/>
                                </attribute-override>
                              </embedded>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(1));

        expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.SuperGamma">
                            <attributes>
                              <id name="id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(2));

        expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.WithMappedSuperclass">
                            <table name="WithMappedSuperclass"/>
                            <attributes>
                              <basic name="URL" access="FIELD">
                              </basic>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(3));

        expected = """
                          <embeddable class="io.openliberty.data.internal.persistence.orm.SuperBeta$Script">
                            <attributes>
                              <basic name="lowercase" access="FIELD">
                                <column nullable="false"/>
                              </basic>
                              <basic name="uppercase" access="FIELD">
                                <column nullable="false"/>
                              </basic>
                            </attributes>
                          </embeddable>
                        """;

        assertEquals(expected, xmls.get(4));
    }

    @Test
    public void mappedSuperClassEmbeddedIdEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(WithMappedSuperclassPrime.class);
        List<String> xmls = p.generateView();

        assertEquals(6, xmls.size());

        String expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.SuperAlpha">
                            <attributes>
                              <version name="version" access="FIELD">
                              </version>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(0));

        expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.SuperBeta">
                            <attributes>
                              <embedded name="script" access="FIELD">
                                <attribute-override name="lowercase">
                                  <column name="SCRIPT_LOWERCASE"/>
                                </attribute-override>
                                <attribute-override name="uppercase">
                                  <column name="SCRIPT_UPPERCASE"/>
                                </attribute-override>
                              </embedded>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(1));

        expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.SuperGammaPrime">
                            <attributes>
                              <embedded-id name="name_id" access="FIELD">
                                <attribute-override name="firstName">
                                  <column name="NAME_ID_FIRSTNAME"/>
                                </attribute-override>
                                <attribute-override name="lastName">
                                  <column name="NAME_ID_LASTNAME"/>
                                </attribute-override>
                              </embedded-id>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(2));

        expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.WithMappedSuperclassPrime">
                            <table name="WithMappedSuperclassPrime"/>
                            <attributes>
                              <basic name="URL" access="FIELD">
                              </basic>
                            </attributes>
                          </entity>
                        """;

        assertEquals(expected, xmls.get(3));

        expected = """
                          <embeddable class="io.openliberty.data.internal.persistence.orm.SuperBeta$Script">
                            <attributes>
                              <basic name="lowercase" access="FIELD">
                                <column nullable="false"/>
                              </basic>
                              <basic name="uppercase" access="FIELD">
                                <column nullable="false"/>
                              </basic>
                            </attributes>
                          </embeddable>
                        """;

        assertEquals(expected, xmls.get(4));

        expected = """
                          <embeddable class="io.openliberty.data.internal.persistence.orm.SuperGammaPrime$Name">
                            <attributes>
                              <basic name="firstName" access="PROPERTY">
                              </basic>
                              <basic name="lastName" access="PROPERTY">
                              </basic>
                            </attributes>
                          </embeddable>
                        """;

        assertEquals(expected, xmls.get(5));
    }

    @Test
    public void converterEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(WithConverter.class);
        List<String> xmls = p.generateView();

        assertEquals(4, xmls.size());

        String expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.WithConverter">
                            <table name="WithConverter"/>
                            <attributes>
                              <id name="id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <basic name="lastName" access="PROPERTY">
                              </basic>
                              <version name="version" access="FIELD">
                              </version>
                              <element-collection name="aliases" access="FIELD" fetch="EAGER">
                              </element-collection>
                            </attributes>
                          </entity>
                        """;
        assertEquals(expected, xmls.get(0));

        expected = """
                          <converter class="io.openliberty.data.internal.persistence.orm.TestConverters$ClassConverter">
                          </converter>
                        """;
        assertEquals(expected, xmls.get(1));

        expected = """
                          <converter class="io.openliberty.data.internal.persistence.orm.TestConverters$FieldConverter">
                          </converter>
                        """;
        assertEquals(expected, xmls.get(2));

        expected = """
                          <converter class="io.openliberty.data.internal.persistence.orm.TestConverters$MethodConverter">
                          </converter>
                        """;
        assertEquals(expected, xmls.get(3));
    }

    @Test
    public void converterComplexEntityTest() {
        EntityParser p = new EntityParser("");
        p.parse(WithConverterComplex.class);
        List<String> xmls = p.generateView();

        assertEquals(6, xmls.size());

        String expected = """
                          <mapped-superclass class="io.openliberty.data.internal.persistence.orm.ConverterSuper">
                            <attributes>
                              <basic name="firstName" access="FIELD">
                              </basic>
                              <embedded name="emb" access="FIELD">
                                <attribute-override name="lastName">
                                  <column name="EMB_LASTNAME"/>
                                </attribute-override>
                              </embedded>
                            </attributes>
                          </mapped-superclass>
                        """;

        assertEquals(expected, xmls.get(0));

        expected = """
                          <entity class="io.openliberty.data.internal.persistence.orm.WithConverterComplex">
                            <table name="WithConverterComplex"/>
                            <attributes>
                              <id name="id" access="FIELD">
                                <column nullable="false"/>
                              </id>
                            </attributes>
                          </entity>
                        """;
        assertEquals(expected, xmls.get(1));

        expected = """
                          <embeddable class="io.openliberty.data.internal.persistence.orm.ConverterEmbedded">
                            <attributes>
                              <basic name="lastName" access="PROPERTY">
                              </basic>
                            </attributes>
                          </embeddable>
                        """;

        assertEquals(expected, xmls.get(2));

        expected = """
                          <converter class="io.openliberty.data.internal.persistence.orm.TestConverters$ClassConverter">
                          </converter>
                        """;
        assertEquals(expected, xmls.get(3));

        expected = """
                          <converter class="io.openliberty.data.internal.persistence.orm.TestConverters$FieldConverter">
                          </converter>
                        """;
        assertEquals(expected, xmls.get(4));

        expected = """
                          <converter class="io.openliberty.data.internal.persistence.orm.TestConverters$MethodConverter">
                          </converter>
                        """;
        assertEquals(expected, xmls.get(5));
    }

}
