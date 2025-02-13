SET GLOBAL time_zone = 'America/Chicago';

USE ganymededb;

CREATE TABLE kingdom (
    kingdom_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(32) NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT 'N/A',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);


CREATE TABLE landscape (
    landscape_id INT AUTO_INCREMENT PRIMARY KEY,
	kingdom_id INT NOT NULL,
    ip VARCHAR(39) NOT NULL,
    hostname VARCHAR(64) NOT NULL DEFAULT 'N/A',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	FOREIGN KEY (kingdom_id) REFERENCES landscape(landscape_id) ON DELETE CASCADE
);

CREATE TABLE ports (
    port_id INT AUTO_INCREMENT PRIMARY KEY,
    landscape_id INT NOT NULL,
    port INT NOT NULL,
    protocol VARCHAR(3) NOT NULL DEFAULT 'TCP',
    FOREIGN KEY (landscape_id) REFERENCES landscape(landscape_id) ON DELETE CASCADE
);





