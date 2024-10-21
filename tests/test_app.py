import unittest
from app import create_app, db
from app.models import User

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        """
        Set up a test environment for the Flask application.
        """
        self.app = create_app('testing')
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            # Create a test user
            user = User(username='testuser', email='testuser@example.com', password_hash='testpassword')
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        """
        Tear down the test environment.
        """
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_home_page(self):
        """
        Test the home page for a successful response.
        """
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_register_user(self):
        """
        Test user registration.
        """
        response = self.client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'password',
            'confirm_password': 'password'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Your account has been created! You are now able to log in', response.data)

    def test_login_user(self):
        """
        Test user login.
        """
        response = self.client.post('/auth/login', data={
            'email': 'testuser@example.com',
            'password': 'testpassword'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)

    def test_logout_user(self):
        """
        Test user logout.
        """
        # Login first
        self.client.post('/auth/login', data={
            'email': 'testuser@example.com',
            'password': 'testpassword'
        }, follow_redirects=True)
        # Logout
        response = self.client.get('/auth/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)

if __name__ == '__main__':
    unittest.main()
