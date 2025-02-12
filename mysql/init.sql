SET GLOBAL time_zone = 'America/Chicago';

USE ganymededb;

CREATE TABLE landscape (
    landscape_id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    hostname VARCHAR(255) NOT NULL DEFAULT 'N/A',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE ports (
    port_id INT AUTO_INCREMENT PRIMARY KEY,
    landscape_id INT NOT NULL,
    port INT NOT NULL,
    protocol VARCHAR(24) NOT NULL DEFAULT '-',
    FOREIGN KEY (landscape_id) REFERENCES landscape(landscape_id) ON DELETE CASCADE
);
