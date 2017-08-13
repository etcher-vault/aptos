import json
import os
import unittest

from aptos import primitive
from aptos.swagger.v3.parser import OpenAPIParser

BASE_DIR = os.path.dirname(__file__)


class OpenAPIVersion3TestCase(unittest.TestCase):

    def runTest(self):
        with open(os.path.join(BASE_DIR, 'schema', 'petstore')) as fp:
            schema = json.load(fp)
        swagger = OpenAPIParser.parse(schema)
        self.assertIsInstance(swagger.paths['/pets']['get'].parameters[0].schema, primitive.Array)  # noqa: E501
        self.assertIsInstance(swagger.paths['/pets']['get'].parameters[0].schema.items, primitive.String)  # noqa: E501
        self.assertIsInstance(swagger.paths['/pets']['get'].parameters[1].schema, primitive.Integer)  # noqa: E501
        self.assertTrue(swagger.paths['/pets']['get'].responses['200'].content['application/json'].schema.items.resolved)  # noqa: E501
        self.assertTrue(swagger.components.schemas['Pet'].allOf[0].resolved)
        self.assertTrue(swagger.paths['/pets']['get'].responses['200'].content['application/json'].schema.items.resolved)  # noqa: E501

        with open(os.path.join(BASE_DIR, 'schema', 'uber')) as fp:
            schema = json.load(fp)
        swagger = OpenAPIParser.parse(schema)
        self.assertTrue(swagger.paths['/products']['get'].responses['200'].content['application/json'].schema.resolved)  # noqa: E501
