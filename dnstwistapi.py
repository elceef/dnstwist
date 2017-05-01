from flask import Flask
from flask_restful import Api

from controllers.FuzzyDomainController import FuzzyDomainsController

app = Flask(__name__)
api = Api(app)

api.add_resource(FuzzyDomainsController, '/v1/fuzzy-domains/<string:domain>/')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
