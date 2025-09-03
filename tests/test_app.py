import pytest
import tempfile
import os
from app import app, init_db, FLAGS, LEVELS

@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    # Create a temporary database file
    db_fd, db_path = tempfile.mkstemp()
    
    # Configure app for testing
    app.config['TESTING'] = True
    app.config['DATABASE'] = db_path
    
    with app.test_client() as client:
        with app.app_context():
            # Initialize the database
            init_db()
        yield client
    
    # Clean up
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def runner():
    """Create a test runner for the Flask application."""
    return app.test_cli_runner()

class TestBasicFunctionality:
    """Test basic application functionality."""
    
    def test_home_page(self, client):
        """Test that the home page loads successfully."""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Cyber Escape' in response.data
    
    def test_health_check(self, client):
        """Test the health check endpoint."""
        response = client.get('/healthz')
        assert response.status_code == 200
        data = response.get_json()
        assert data['ok'] == True
        assert 'timestamp' in data

class TestLevels:
    """Test level functionality."""
    
    def test_level_1_access(self, client):
        """Test that level 1 is accessible."""
        response = client.get('/level/1')
        assert response.status_code == 200
        assert b'Level 1: View Source' in response.data
    
    def test_level_2_access(self, client):
        """Test that level 2 is accessible."""
        response = client.get('/level/2')
        assert response.status_code == 200
        assert b'Level 2: Unicode Tricks' in response.data
    
    def test_level_3_access(self, client):
        """Test that level 3 is accessible."""
        response = client.get('/level/3')
        assert response.status_code == 200
        assert b'Level 3: EXIF Metadata' in response.data
    
    def test_level_4_access(self, client):
        """Test that level 4 is accessible."""
        response = client.get('/level/4')
        assert response.status_code == 200
        assert b'Level 4: Git History' in response.data
    
    def test_level_5_access(self, client):
        """Test that level 5 is accessible."""
        response = client.get('/level/5')
        assert response.status_code == 200
        assert b'Level 5: Template Injection' in response.data
    
    def test_level_6_access(self, client):
        """Test that level 6 is accessible."""
        response = client.get('/level/6')
        assert response.status_code == 200
        assert b'Level 6: Race Condition' in response.data
    
    def test_invalid_level(self, client):
        """Test that invalid level redirects to home."""
        response = client.get('/level/999')
        assert response.status_code == 302  # Redirect

class TestFlagSubmission:
    """Test flag submission functionality."""
    
    def test_level_1_correct_flag(self, client):
        """Test correct flag submission for level 1."""
        response = client.post('/level/1/submit', data={'code': FLAGS[1]})
        assert response.status_code == 302  # Redirect to next level
    
    def test_level_1_incorrect_flag(self, client):
        """Test incorrect flag submission for level 1."""
        response = client.post('/level/1/submit', data={'code': 'WRONG_FLAG'})
        assert response.status_code == 200
        assert b'Incorrect flag' in response.data
    
    def test_level_2_correct_flag(self, client):
        """Test correct flag submission for level 2."""
        # First complete level 1
        client.post('/level/1/submit', data={'code': FLAGS[1]})
        # Then try level 2
        response = client.post('/level/2/submit', data={'code': FLAGS[2]})
        assert response.status_code == 302  # Redirect to next level

class TestHints:
    """Test hint functionality."""
    
    def test_get_hint_level_1(self, client):
        """Test getting a hint for level 1."""
        response = client.get('/level/1/hint')
        assert response.status_code == 200
        data = response.get_json()
        assert 'hint' in data
        assert 'hints_left' in data
        assert 'score' in data
    
    def test_hint_penalty(self, client):
        """Test that hints reduce score."""
        # Get initial score
        client.post('/level/1/submit', data={'code': FLAGS[1]})
        
        # Get a hint
        response = client.get('/level/1/hint')
        data = response.get_json()
        assert data['score'] < 100  # Score should be reduced
    
    def test_max_hints(self, client):
        """Test that maximum hints are enforced."""
        # Get all hints
        for _ in range(3):
            client.get('/level/1/hint')
        
        # Try to get another hint
        response = client.get('/level/1/hint')
        assert response.status_code == 400
        data = response.get_json()
        assert 'No hints left' in data['error']

class TestRaceCondition:
    """Test race condition level functionality."""
    
    def test_race_balance(self, client):
        """Test race balance endpoint."""
        response = client.get('/race/balance')
        assert response.status_code == 200
        data = response.get_json()
        assert 'balance' in data
        assert data['balance'] == 60  # Initial balance
    
    def test_race_buy_insufficient_funds(self, client):
        """Test buying flag with insufficient funds."""
        response = client.post('/race/buy')
        assert response.status_code == 400
        data = response.get_json()
        assert 'Insufficient balance' in data['error']

class TestAdminPanel:
    """Test admin panel functionality."""
    
    def test_admin_access(self, client):
        """Test that admin panel is accessible."""
        response = client.get('/admin')
        assert response.status_code == 200
        assert b'Admin Panel' in response.data

class TestConfiguration:
    """Test application configuration."""
    
    def test_levels_configuration(self):
        """Test that all levels are properly configured."""
        assert len(LEVELS) == 6
        for level_num in range(1, 7):
            assert level_num in LEVELS
            level = LEVELS[level_num]
            assert 'name' in level
            assert 'difficulty' in level
            assert 'points' in level
            assert 'hints' in level
    
    def test_flags_configuration(self):
        """Test that all flags are properly configured."""
        assert len(FLAGS) == 6
        for level_num in range(1, 7):
            assert level_num in FLAGS
            flag = FLAGS[level_num]
            assert flag.startswith('FLAG{')
            assert flag.endswith('}')

class TestDatabase:
    """Test database functionality."""
    
    def test_database_initialization(self, client):
        """Test that database is properly initialized."""
        # The database should be created when the app starts
        # This is tested by the fact that we can access levels
        response = client.get('/level/1')
        assert response.status_code == 200

class TestSecurity:
    """Test security features."""
    
    def test_session_creation(self, client):
        """Test that sessions are created properly."""
        response = client.get('/')
        # Check that a session cookie is set
        assert 'session' in response.headers.get('Set-Cookie', '')

if __name__ == '__main__':
    pytest.main([__file__])
