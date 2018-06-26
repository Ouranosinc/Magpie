# -- Cornice (display swagger REST API docs)
import colander
from cornice import Service
from cornice.service import get_services
from cornice.validators import colander_body_validator
from cornice_swagger.swagger import CorniceSwagger
