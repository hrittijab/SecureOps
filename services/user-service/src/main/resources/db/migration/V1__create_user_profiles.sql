CREATE TABLE user_profiles (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    address VARCHAR(500),
    account_tier VARCHAR(50) NOT NULL DEFAULT 'STANDARD',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO user_profiles (
    id,
    email,
    full_name,
    phone,
    address,
    account_tier
)
VALUES
(
    '11111111-1111-1111-1111-111111111111',
    'alice@secureops.local',
    'Alice Example',
    '+1-555-0101',
    '101 SecureOps Avenue',
    'STANDARD'
),
(
    '22222222-2222-2222-2222-222222222222',
    'bob@secureops.local',
    'Bob Example',
    '+1-555-0102',
    '202 SecureOps Avenue',
    'PREMIUM'
);