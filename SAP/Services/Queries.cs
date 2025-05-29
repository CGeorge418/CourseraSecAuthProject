using Microsoft.Data.Sqlite;

namespace SecAuthProj {
    public class SQLWizard {

        private readonly SqliteConnection _connection;

        public SQLWizard() {
            _connection = new("Data Source=C:\\Users\\cgeorge.MECOJAX\\Coursera\\SecurityAndAuthentication\\Project\\SAP\\data.db;");
            OpenConnection();
            CreateTable();
        }

        // ~SQLWizard() {
        //     try {
        //         new SqliteCommand("DROP TABLE IF EXISTS Users", _connection).ExecuteNonQuery();
        //     }
        //     catch (SqliteException ex) {
        //         Console.WriteLine($"Error dropping table: {ex.Message}");
        //     }
        //     finally {
        //         CloseConnection();
        //         _connection.Dispose();
        //     }
        // }

        private void OpenConnection() {
            if (_connection.State != System.Data.ConnectionState.Open) {
                _connection.Open();
            }
        }

        private void CloseConnection() {
            if (_connection.State != System.Data.ConnectionState.Closed) {
                _connection.Close();
            }
        }

        private void CreateTable() {
            string query = "CREATE TABLE Users ("
                             + "UserID INTEGER PRIMARY KEY, "
                             + "Username VARCHAR(100), "
                             + "Email VARCHAR(100), "
                             + "PasswordHash VARCHAR(255), "
                             + "Role VARCHAR(10)"
                         + ")";
            SqliteCommand command = new(query, _connection);

            try {
                int rows = command.ExecuteNonQuery();
                Console.WriteLine("Table created successfully.");
                InsertData();
            } catch (SqliteException ex) {
                Console.WriteLine($"Error creating table: {ex.Message}");
            }
        }

        private void InsertData() {
            string query = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES ('user1', 'email1@email.com', $Password1, 'Admin'), ('user2', 'email2@email.com', $Password2, 'Admin'), ('user3', 'email3@email.com', $Password3, 'User')";            
            SqliteCommand command = new(query, _connection);
            command.Parameters.AddWithValue("$Password1", EncryptionHelper.HashPassword("password1"));
            command.Parameters.AddWithValue("$Password2", EncryptionHelper.HashPassword("password2"));
            command.Parameters.AddWithValue("$Password3", EncryptionHelper.HashPassword("password3"));

            try {
                command.ExecuteNonQuery();
            } catch (SqliteException ex) {
                Console.WriteLine($"Error inserting data: {ex.Message}");
            }
        }

        public bool GetUserQuery(string username, string email, string hashed_password, out string[] user_entry) {
            user_entry = [];

            string query = "SELECT * FROM Users WHERE Username = $Username AND Email = $Email AND PasswordHash = $PasswordHash";
            SqliteCommand command = new(query, _connection);
            command.Parameters.AddWithValue("$Username", username);
            command.Parameters.AddWithValue("$Email", email);
            command.Parameters.AddWithValue("$PasswordHash", hashed_password);

            SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read()) {
                string userName = reader["Username"].ToString() ?? "";
                string userEmail = reader["Email"].ToString() ?? "";
                string userRole = reader["Role"].ToString() ?? "";
                
                Console.WriteLine($"User: {userName}, Email: {userEmail}, Role: {userRole}");
                if (user_entry.Length == 0) {
                    user_entry = new string[3] {
                        userName,
                        userEmail,
                        userRole
                    };
                }
            }
            bool has_rows = reader.HasRows;
            reader.Close();

            return has_rows;
        }
    }
}