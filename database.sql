
CREATE TABLE tienda_cluster.role (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(25) NOT NULL,
  PRIMARY KEY (id)
);

INSERT INTO tienda_cluster.role (name) 
values ('admin'), ('user');

CREATE TABLE tienda_cluster.user (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  active TINYINT(1) NOT NULL DEFAULT 1,
  roleId INT UNSIGNED NOT NULL DEFAULT 1,
  email VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  createdAt DATETIME NOT NULL,
  updatedAt DATETIME NOT NULL,
  deletedAt DATETIME NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (roleId) REFERENCES role (id)
);

CREATE TABLE tienda_cluster.session (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  userId INT UNSIGNED NOT NULL, 
  refreshToken VARCHAR(255) NOT NULL, 
  createdAt DATETIME NOT NULL,
  updatedAt DATETIME NOT NULL,
  deletedAt DATETIME NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (userId) REFERENCES user (id)
);