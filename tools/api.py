#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask
from flask_restful import Api, Resource

from dnstwist import UrlParser, DomainFuzz


class Fuzz(Resource):
    def get(self, domain):
        try:
            url = UrlParser(domain)
        except ValueError as err:
            return err, 400

        domain_fuzz = DomainFuzz(url.domain)
        domain_fuzz.generate()

        return domain_fuzz.domains


app = Flask(__name__)
api = Api(app)

api.add_resource(Fuzz, '/fuzz/<string:domain>', strict_slashes=False)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
