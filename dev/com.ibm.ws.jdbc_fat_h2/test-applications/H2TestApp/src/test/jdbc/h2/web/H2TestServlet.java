/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package test.jdbc.h2.web;

import static java.sql.Connection.TRANSACTION_NONE;
import static java.sql.Connection.TRANSACTION_READ_COMMITTED;
import static java.sql.Connection.TRANSACTION_READ_UNCOMMITTED;
import static java.sql.Connection.TRANSACTION_REPEATABLE_READ;
import static java.sql.Connection.TRANSACTION_SERIALIZABLE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.List;

import jakarta.annotation.Resource;
import jakarta.annotation.sql.DataSourceDefinition;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.transaction.UserTransaction;

import javax.sql.ConnectionPoolDataSource;
import javax.sql.DataSource;
import javax.sql.PooledConnection;

import org.junit.Test;

import componenttest.app.FATServlet;

@DataSourceDefinition(name = "java:comp/jdbc/H2ConnectionPoolDataSource",
                      className = "javax.sql.ConnectionPoolDataSource",
                      url = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
                      user = "dbuser1",
                      password = "dbpwd1")
@SuppressWarnings("serial")
@WebServlet("/*")
public class H2TestServlet extends FATServlet {
    @Resource(lookup = "java:comp/jdbc/H2ConnectionPoolDataSource")
    DataSource h2cpDataSource;

    @Resource
    UserTransaction tx;

    static record Compound(
                    String formula,
                    String name,
                    int calcium,
                    int carbon,
                    int chlorine,
                    int fluorine,
                    int hydrogen,
                    int nitrogen,
                    int oxygen,
                    int sodium,
                    int sulfur) {
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        try (Connection con = h2cpDataSource.getConnection()) {
            Statement stmt = con.createStatement();
            stmt.execute("""
                            CREATE TABLE COMPOUNDS (
                                FORMULA VARCHAR(50) NOT NULL PRIMARY KEY,
                                NAME VARCHAR(100) NOT NULL,
                                CALCIUM SMALLINT CHECK (CALCIUM >= 0),
                                CARBON SMALLINT CHECK (CARBON >= 0),
                                CHLORINE SMALLINT CHECK (CHLORINE >= 0),
                                FLUORINE SMALLINT CHECK (FLUORINE >= 0),
                                HYDROGEN SMALLINT CHECK (HYDROGEN >= 0),
                                NITROGEN SMALLINT CHECK (NITROGEN >= 0),
                                OXYGEN SMALLINT CHECK (OXYGEN >= 0),
                                SODIUM SMALLINT CHECK (SODIUM >= 0),
                                SULFUR SMALLINT CHECK (SULFUR >= 0)
                            )
                            """);
            String addCompound = "INSERT INTO COMPOUNDS VALUES (?,?,?,?,?,?,?,?,?,?,?)";
            PreparedStatement ps = con.prepareStatement(addCompound);
            //                      Ca C  Cl F  H  N  O  Na S
            List.of(new Compound("C3H8", "Propane", //
                            /*   */ 0, 3, 0, 0, 8, 0, 0, 0, 0),
                    new Compound("CH4", "Methane", //
                                    0, 1, 0, 0, 4, 0, 0, 0, 0),
                    new Compound("CO2", "Carbon dioxide", //
                                    0, 1, 0, 0, 0, 0, 2, 0, 0),
                    new Compound("CaCO3", "Calcium carbonate", //
                                    1, 1, 0, 0, 0, 0, 3, 0, 0),
                    new Compound("CaCl2", "Calcium chloride", //
                                    1, 0, 2, 0, 0, 0, 0, 0, 0),
                    new Compound("CaO", "Calcium oxide", //
                                    1, 0, 0, 0, 0, 0, 1, 0, 0),
                    new Compound("H2", "Hydrogen", //
                                    0, 0, 0, 0, 2, 0, 0, 0, 0),
                    new Compound("H2O", "Water", //
                                    0, 0, 0, 0, 2, 0, 1, 0, 0),
                    new Compound("H2O2", "Hydrogen peroxide", //
                                    0, 0, 0, 0, 2, 0, 2, 0, 0),
                    new Compound("H2S", "Hydrogen sulfide", //
                                    0, 0, 0, 0, 2, 0, 0, 0, 1),
                    new Compound("H2SO4", "Sulfuric acid", //
                                    0, 0, 0, 0, 2, 0, 4, 0, 1),
                    new Compound("HCl", "Hydrochloric acid", //
                                    0, 0, 1, 0, 1, 0, 0, 0, 0),
                    new Compound("HF", "Hydrofluoric acid", //
                                    0, 0, 0, 1, 1, 0, 0, 0, 0),
                    new Compound("N2H4", "Hydrazine", //
                                    0, 0, 0, 0, 4, 2, 0, 0, 0),
                    new Compound("NH3", "Ammonia", //
                                    0, 0, 0, 0, 3, 1, 0, 0, 0),
                    new Compound("NaCl", "Sodium chloride", //
                                    0, 0, 1, 0, 0, 0, 0, 1, 0),
                    new Compound("NaOH", "Sodium hydroxide", //
                                    0, 0, 0, 0, 1, 0, 1, 1, 0))
                            .forEach(c -> {
                                try {
                                    ps.setString(1, c.formula);
                                    ps.setString(2, c.name);
                                    ps.setInt(3, c.calcium);
                                    ps.setInt(4, c.carbon);
                                    ps.setInt(5, c.chlorine);
                                    ps.setInt(6, c.fluorine);
                                    ps.setInt(7, c.hydrogen);
                                    ps.setInt(8, c.nitrogen);
                                    ps.setInt(9, c.oxygen);
                                    ps.setInt(10, c.sodium);
                                    ps.setInt(11, c.sulfur);
                                    ps.addBatch();
                                } catch (SQLException x) {
                                    throw new RuntimeException(x);
                                }
                            });
            ps.executeBatch();
        } catch (SQLException x) {
            throw new ServletException(x.getMessage(), x);
        }
    }

    /**
     * Use a DataSource that accesses H2 via the
     * javax.sql.ConnectionPoolDataSource interface.
     */
    @Test
    public void testConnectionPoolDataSource() throws Exception {
        try (Connection con = h2cpDataSource.getConnection()) {
            assertEquals(true, con.getAutoCommit());
            assertEquals("TESTDB", con.getCatalog());
            assertEquals("PUBLIC", con.getSchema());
            assertEquals(TRANSACTION_READ_COMMITTED,
                         con.getTransactionIsolation());

            DatabaseMetaData mdata = con.getMetaData();
            assertEquals("DBUSER1", mdata.getUserName());
            assertEquals("H2", mdata.getDatabaseProductName());
            assertEquals("H2 JDBC Driver", mdata.getDriverName());
            assertEquals(4, mdata.getJDBCMajorVersion());
            assertEquals(3, mdata.getJDBCMinorVersion());

            assertEquals(TRANSACTION_READ_COMMITTED,
                         mdata.getDefaultTransactionIsolation());
            assertEquals(false,
                         mdata.supportsTransactionIsolationLevel(TRANSACTION_NONE));
            assertEquals(true,
                         mdata.supportsTransactionIsolationLevel(TRANSACTION_READ_UNCOMMITTED));
            assertEquals(true,
                         mdata.supportsTransactionIsolationLevel(TRANSACTION_READ_COMMITTED));
            assertEquals(true,
                         mdata.supportsTransactionIsolationLevel(TRANSACTION_REPEATABLE_READ));
            assertEquals(true,
                         mdata.supportsTransactionIsolationLevel(TRANSACTION_SERIALIZABLE));

            assertEquals(true,
                         h2cpDataSource.isWrapperFor(ConnectionPoolDataSource.class));
            ConnectionPoolDataSource cpds = //
                            h2cpDataSource.unwrap(ConnectionPoolDataSource.class);

            // disallowed usage
            try {
                PooledConnection pcon = cpds.getPooledConnection();
                fail("Unsafe getPooledConnection operation on unwrapped" +
                     " instance should have been blocked. Instead: " + pcon);
            } catch (SQLFeatureNotSupportedException x) {
                if (x.getMessage() == null ||
                    !x.getMessage().contains("DSRA9130E"))
                    throw x;
            }

            // valid usage
            PreparedStatement pstmt = con.prepareStatement("""
                            SELECT OXYGEN
                              FROM COMPOUNDS
                             WHERE FORMULA=?
                               FOR UPDATE WAIT 30
                            """);
            pstmt.setString(1, "CO2");
            ResultSet result = pstmt.executeQuery();
            assertEquals(true, result.next());
            assertEquals(2, result.getInt(1));
            assertEquals(false, result.next());
        }
    }
}
