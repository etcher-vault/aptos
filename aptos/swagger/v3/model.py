from copy import deepcopy

from ...primitive import Component, Creator, SchemaMap


class OpenAPI(Component):

    """This is the root document object of the
    `OpenAPI document <https://swagger.io/specification/#oasDocument>`_.
    """

    def __init__(self, openapi='3.0.0', info=None, servers=None, paths=None,
                 components=None, security=None, tags=None, externalDocs=None):
        self.openapi = openapi
        self.info = Info() if info is None else info
        self.servers = [] if servers is None else servers
        self.paths = Paths() if paths is None else paths
        self.components = Components() if components is None else components
        self.security = security
        self.tags = Tags() if tags is None else tags
        self.externalDocs = (
            ExternalDocumentation() if externalDocs is None else externalDocs)

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['info'] = Info.unmarshal(schema.get('info', {}))
        schema['paths'] = Paths.unmarshal(schema.get('paths', {}))
        schema['components'] = (
            Components.unmarshal(schema.get('components', {})))
        schema['tags'] = Tags.unmarshal(schema.get('tags', []))
        schema['externalDocs'] = (
            ExternalDocumentation(**schema.get('externalDocs', {})))
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_specification(self, *args)


class Components(Component):

    def __init__(self, schemas=None, responses=None, parameters=None,
                 examples=None, requestBodies=None, headers=None,
                 securitySchemes=None, links=None, callbacks=None):
        self.schemas = Schemas() if schemas is None else schemas
        self.responses = Responses() if responses is None else responses
        self.parameters = Parameters() if parameters is None else parameters
        self.examples = examples
        self.requestBodies = (
            RequestBodies() if requestBodies is None else requestBodies)
        self.headers = Headers() if headers is None else headers
        self.securitySchemes = (
            SecuritySchemes() if securitySchemes is None else SecuritySchemes())  # noqa: E501
        self.links = links
        self.callbacks = Callbacks() if callbacks is None else callbacks

    @classmethod
    def unmarshal(cls, schema):
        schema['schemas'] = Schemas.unmarshal(schema.get('schemas', {}))
        schema['responses'] = Responses.unmarshal(schema.get('responses', {}))
        schema['parameters'] = (
            Parameters.unmarshal(schema.get('parameters', {})))
        schema['requestBodies'] = (
            RequestBodies.unmarshal(schema.get('requestBodies', {})))
        schema['headers'] = Headers.unmarshal(schema.get('headers', {}))
        schema['securitySchemes'] = (
            SecuritySchemes.unmarshal(schema.get('securitySchemes', {})))
        schema['callbacks'] = Callbacks.unmarshal(schema.get('callbacks', {}))
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_components(self, *args)


class Schemas(SchemaMap):

    def accept(self, visitor, *args):
        return visitor.visit_schemas(self, *args)


class RequestBodies(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: RequestBody.unmarshal(member)
            for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_request_bodies(self, *args)


class Headers(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: Header.unmarshal(member) for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_headers(self, *args)


class SecuritySchemes(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: SecurityScheme.unmarshal(member)
            for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_security_schemes(self, *args)


class Callbacks(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: Callback.unmarshal(member)
            for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_callbacks(self, *args)


class Callback(dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: PathItem.unmarshal(member)
            for name, member in schema.items()})


class Info(Component):

    def __init__(self, title='', description='', termsOfService='',
                 contact=None, license=None, version=''):
        self.title = title
        self.description = description
        self.termsOfService = termsOfService
        self.contact = Contact() if contact is None else contact
        self.license = License() if license is None else license
        self.version = version

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['contact'] = Contact(**schema.get('contact', {}))
        schema['license'] = License(**schema.get('license', {}))
        return cls(**schema)


class ExternalDocumentation(Component):

    def __init__(self, description='', url=''):
        self.description = description
        self.url = url


class Contact(Component):

    def __init__(self, name='', url='', email=''):
        self.name = name
        self.url = url
        self.email = email


class License(Component):

    def __init__(self, name='', url=''):
        self.name = name
        self.url = url


class Variables(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: ServerVariable(**member) for name, member in schema.items()})


class ServerVariable(Component):

    def __init__(self, enum=None, default='', description=''):
        self.enum = enum
        self.default = default
        self.description = description


class Server(Component):

    def __init__(self, url='', description='', variables=None):
        self.url = url
        self.description = description
        self.variables = Variables() if variables is None else variables

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['variables'] = Variables.unmarshal(schema.get('variables', {}))
        return cls(**schema)


class Response(Component):

    def __init__(self, description='', headers=None, content=None, links=None):
        self.description = description
        self.headers = headers
        self.content = Content() if content is None else content
        self.links = links

    @classmethod
    def unmarshal(cls, schema):
        if schema.get('content') is not None:
            schema['content'] = Content.unmarshal(schema['content'])
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_response(self, *args)


class Responses(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: Response.unmarshal(member)
            for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_responses(self, *args)


class Operation(Component):

    def __init__(self, tags=None, summary='', description='',
                 externalDocs=None, operationId='', parameters=None,
                 requestBody=None, responses=None, callbacks=None,
                 deprecated=False, security=None, servers=None):
        # A list of tags for API documentation control. Tags can be used for
        # logical grouping of operations by resources or any other qualifier.
        self.tags = [] if tags is None else list(set(tags))
        self.summary = summary
        self.description = description
        self.externalDocs = (
            ExternalDocumentation() if externalDocs is None else externalDocs)
        self.operationId = operationId
        self.parameters = Parameters() if parameters is None else parameters
        self.requestBody = (
            RequestBody() if requestBody is None else requestBody)
        self.responses = Responses() if responses is None else responses
        self.callbacks = Callbacks() if callbacks is None else callbacks
        self.deprecated = deprecated
        self.security = security
        self.servers = servers

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['externalDocs'] = (
            ExternalDocumentation(**schema.get('externalDocs', {})))
        schema['parameters'] = (
            Parameters.unmarshal(schema.get('parameters', [])))
        if schema.get('requestBody') is not None:
            schema['requestBody'] = (
                RequestBody.unmarshal(schema['requestBody']))
        schema['responses'] = Responses.unmarshal(schema['responses'])
        schema['callbacks'] = Callbacks.unmarshal(schema.get('callbacks', {}))
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_operation(self, *args)


class RequestBody(Component):

    def __init__(self, description='', content=None, required=False):
        self.description = description
        self.content = Content() if content is None else content
        self.required = required

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['content'] = Content.unmarshal(schema['content'])
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_request_body(self, *args)


class Content(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: MediaType.unmarshal(member)
            for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_content(self, *args)


class MediaType(Component):

    def __init__(self, schema=None, example=None, examples=None,
                 encoding=None):
        self.schema = schema
        self.example = example
        self.examples = examples
        self.encoding = encoding

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        if schema.get('schema') is not None:
            schema['schema'] = (
                Creator.create(schema['schema'].get('type'))
            ).unmarshal(schema['schema'])
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_media_type(self, *args)


class PathItem(Component, dict):

    def __init__(self, summary='', description='', servers=None,
                 parameters=None, **kwargs):
        super().__init__(**kwargs)
        self.reference = kwargs.get('reference', '')
        self.summary = summary
        self.description = description
        self.servers = [] if servers is None else servers
        self.parameters = Parameters() if parameters is None else parameters

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        for operation in ('get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'):  # noqa: E501
            if schema.get(operation) is not None:
                schema[operation] = Operation.unmarshal(schema[operation])
        schema['parameters'] = (
            Parameters.unmarshal(schema.get('parameters', [])))
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_path_item(self, *args)


class Paths(Component, dict):

    @classmethod
    def unmarshal(cls, schema):
        return cls({
            name: PathItem.unmarshal(member)
            for name, member in schema.items()})

    def accept(self, visitor, *args):
        return visitor.visit_paths(self, *args)


class Parameters(Component, list):

    @classmethod
    def unmarshal(cls, schema):
        return cls(Parameter.unmarshal(element) for element in schema)

    def accept(self, visitor, *args):
        return visitor.visit_parameters(self, *args)


class Parameter(Component):

    def __init__(self, name='', description='', required=False,
                 deprecated=False, allowEmptyValue=False, style='',
                 explode=False, allowReserved=False, schema=None, example=None,
                 examples=None, content=None, **kwargs):
        # TODO: complete `Parameter` class
        parameterIn = kwargs.get('in', '')
        assert parameterIn in ('query', 'header', 'path', 'cookie')
        self.name = name
        self.parameterIn = parameterIn
        self.description = description
        self.required = required
        self.deprecated = deprecated
        self.allowEmptyValue = allowEmptyValue
        self.style = style
        self.explode = explode
        self.allowReserved = allowReserved
        self.schema = schema
        self.example = example
        self.examples = examples
        self.content = Content() if content is None else content

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        if schema.get('schema') is not None:
            schema['schema'] = (
                Creator.create(schema['schema'].get('type'))
            ).unmarshal(schema['schema'])
        return cls(**schema)

    def accept(self, visitor, *args):
        return visitor.visit_parameter(self, *args)


class Header(Component):

    def __init__(self, description='', required=False, deprecated=False,
                 allowEmptyValue=False, style='', explode=False,
                 allowReserved=False, schema=None, example=None,
                 examples=None):
        self.description = description
        self.required = required
        self.deprecated = deprecated
        self.allowEmptyValue = allowEmptyValue
        self.style = style
        self.explode = explode
        self.allowReserved = allowReserved
        self.schema = schema
        self.example = example
        self.examples = examples


class OAuthFlows:

    def __init__(self, implicit=None, password=None, clientCredentials=None,
                 authorizationCode=None):
        self.implicit = OAuthFlow() if implicit is None else implicit
        self.password = OAuthFlow() if password is None else password
        self.clientCredentials = (
            OAuthFlow() if clientCredentials is None else clientCredentials)
        self.authorizationCode = (
            OAuthFlow() if authorizationCode is None else authorizationCode)

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['implicit'] = OAuthFlow(**schema.get('implicit', {}))
        schema['password'] = OAuthFlow(**schema.get('password', {}))
        schema['clientCredentials'] = (
            OAuthFlow(**schema.get('clientCredentials', {})))
        schema['authorizationCode'] = (
            OAuthFlow(**schema.get('authorizationCode', {})))
        return cls(**schema)


class OAuthFlow:

    def __init__(self, authorizationUrl='', tokenUrl='', refreshUrl='',
                 scopes=None):
        self.authorizationUrl = authorizationUrl
        self.tokenUrl = tokenUrl
        self.refreshUrl = refreshUrl
        self.scopes = {} if scopes is None else dict(scopes)


class SecurityScheme:

    def __init__(self, type='', description='', name='', scheme='',
                 bearerFormat='', flows=None, openIdConnectUrl='', **kwargs):
        assert type in ('apiKey', 'http', 'oauth2', 'openIdConnect',)
        self.type = type
        self.description = description
        self.name = name
        parameterIn = kwargs.get('in', '')
        assert parameterIn in ('query', 'header', 'cookie',)
        self.parameterIn = parameterIn
        self.scheme = scheme
        self.bearerFormat = bearerFormat
        self.flows = OAuthFlows() if flows is None else flows
        self.openIdConnectUrl = openIdConnectUrl

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['flows'] = OAuthFlows.unmarshal(schema.get('flows', {}))
        return cls(**schema)


class Tag:

    def __init__(self, name='', description='', externalDocs=None):
        self.name = name
        self.description = description
        self.externalDocs = (
            ExternalDocumentation() if externalDocs is None else externalDocs)

    @classmethod
    def unmarshal(cls, schema):
        schema = deepcopy(schema)
        schema['externalDocs'] = (
            ExternalDocumentation(**schema.get('externalDocs', {})))
        return cls(**schema)


class Tags(list):

    @classmethod
    def unmarshal(cls, schema):
        return cls(Tag.unmarshal(element) for element in schema)
