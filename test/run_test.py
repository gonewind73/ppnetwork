'''
Created on 2018年5月22日

@author: heguofeng
'''
import unittest

if __name__ == "__main__":
    suite = unittest.TestLoader().discover("test", "test*.py" )
    unittest.TextTestRunner(verbosity=2).run(suite)