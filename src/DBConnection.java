import java.sql.*;
import com.mysql.jdbc.jdbc2.optional.*;

public class DBConnection {

    private static MysqlConnectionPoolDataSource ds;
    private Connection conn;

    public void setup() throws SQLException {
        ds = new MysqlConnectionPoolDataSource();
        ds.setUser("USER");
        ds.setPassword("PASSWORD");
        ds.setServerName("localhost");
        ds.setDatabaseName("DB_NAME");
    }

    public DBConnection() {
        try {
            setup();
            conn = ds.getConnection();
            conn.setTransactionIsolation(conn.TRANSACTION_READ_COMMITTED);
            conn.setAutoCommit(false);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public Connection getConnection() {
        return conn;
    }
}
