"""Integration tests: run `python -m unittest tests.py` after installing Flask."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

class PlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ['PHYSIX_DATA_DIR'] = cls.tmp.name
        spec = importlib.util.spec_from_file_location('physix_server_for_tests', Path(__file__).with_name('app.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.module = module

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        os.environ.pop('PHYSIX_DATA_DIR', None)

    def setUp(self):
        self.client = self.module.app.test_client()
        self.client2 = self.module.app.test_client()
        self.client3 = self.module.app.test_client()
        with self.module.app.app_context():
            db = self.module.connection()
            db.execute('DELETE FROM notes')
            db.execute("DELETE FROM users WHERE role='student'")
            db.execute("DELETE FROM users WHERE role='curator'")
            db.commit()

    def csrf(self, client):
        return client.get('/api/me').get_json()['csrf']

    def write(self, client, path, payload, method='post'):
        token=self.csrf(client)
        return getattr(client, method)(path, json=payload, headers={'X-CSRF-Token': token})

    def signup(self, client, name, email, role, code=None):
        r=self.write(client,'/api/register', {'name':name,'email':email,'password':'Safe-Pass-1234', 'role':role,'curatorCode':code or ''})
        self.assertEqual(r.status_code,201, r.get_json())
        self.assertIsNone(client.get('/api/me').get_json()['user'])
        wrong=self.write(client,'/api/login',{'email':email,'password':'wrong-password'})
        self.assertEqual(wrong.status_code,401)
        logged=self.write(client,'/api/login',{'email':email,'password':'Safe-Pass-1234'})
        self.assertEqual(logged.status_code,200,logged.get_json())
        return logged.get_json()['user']

    def test_registration_login_and_saved_progress(self):
        student=self.signup(self.client,'Айжан А','student1@example.com','student')
        self.assertEqual(student['role'],'student')
        self.assertEqual(self.client.get('/api/students').status_code,403)
        progress={'done':['k1','k2'],'quizzes':{'k1':{'score':4,'percent':80,'date':'2026-10-24'}},'problems':[], 'labsDone':[], 'labsScores':{}}
        r=self.write(self.client, '/api/progress', progress, method='put')
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.client.get('/api/me').get_json()['progress']['done'],['k1','k2'])
        self.assertEqual(self.write(self.client,'/api/logout',{}).status_code,200)
        self.assertEqual(self.client.get('/api/me').get_json()['user'], None)
        again=self.write(self.client,'/api/login',{'email':'student1@example.com','password':'Safe-Pass-1234'})
        self.assertEqual(again.get_json()['progress']['done'],['k1','k2'])

    def test_curator_group_scope_and_notes(self):
        cur1=self.signup(self.client,'Марат Мұғалім','cur1@example.com','curator')
        cur2=self.signup(self.client2,'Дина Мұғалім','cur2@example.com','curator')
        self.assertNotEqual(cur1['curatorCode'],cur2['curatorCode'])
        student=self.signup(self.client3,'Айжан Оқушы','student1@example.com','student',cur1['curatorCode'])
        self.assertEqual(len(self.client.get('/api/students').get_json()['students']),1)
        self.assertEqual(len(self.client2.get('/api/students').get_json()['students']),0)
        self.assertEqual(self.client3.get('/api/students').status_code,403)
        # A curator cannot read/change another curator's student notes.
        forbidden=self.write(self.client2,f'/api/students/{student["id"]}/note',{'note':'X'},method='put')
        self.assertEqual(forbidden.status_code,404)
        saved=self.write(self.client,f'/api/students/{student["id"]}/note',{'note':'Тесті аяқтады'},method='put')
        self.assertEqual(saved.status_code,200)
        self.assertEqual(self.client.get('/api/students').get_json()['students'][0]['note'],'Тесті аяқтады')
        # Student can change group with a code; old curator no longer sees them.
        moved=self.write(self.client3,'/api/student/join',{'code':cur2['curatorCode']})
        self.assertEqual(moved.status_code,200)
        self.assertEqual(len(self.client.get('/api/students').get_json()['students']),0)
        self.assertEqual(len(self.client2.get('/api/students').get_json()['students']),1)

    def test_validation_and_role_guards(self):
        r=self.write(self.client,'/api/register',{'name':'X','email':'bad','password':'123','role':'curator'})
        self.assertEqual(r.status_code,400)
        self.signup(self.client,'Айжан А','student1@example.com','student')
        self.assertEqual(self.write(self.client,'/api/curator/demo',{}).status_code,403)
        self.assertEqual(self.write(self.client,'/api/student/join',{'code':'INVALID!'}).status_code,404)
        self.assertEqual(self.client.put('/api/progress', json={'done': []}).status_code,403)  # CSRF required

if __name__ == '__main__': unittest.main()
