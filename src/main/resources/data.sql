INSERT INTO my_users(username, password, enabled)
    VALUES('user',
    'pass',
    true);

INSERT INTO my_users(username, password, enabled)
    VALUES('admin',
    'pass',
    true);

INSERT INTO my_authorities(username, authority)
    VALUES('user',
    'ROLE_USER');

INSERT INTO my_authorities(username, authority)
    VALUES('admin',
    'ROLE_ADMIN');
