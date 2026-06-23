CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO accounts (username, password) VALUES 
('admin', 'p@ssword123'),
('dev_user', 'secret_key'),
('guest1', '12345'),
('guest2', '12344'),
('guest3', '12343'),
('guest4', '12342'),
('guest5', '12341'),
('guest6', '12340');
