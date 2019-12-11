# -- Cornice (display swagger REST API docs)
# noinspection PyUnresolvedReferences
import colander                                             # noqa: F401,W0611
# noinspection PyUnresolvedReferences
from cornice import Service                                 # noqa: F401,W0611
# noinspection PyUnresolvedReferences
from cornice.service import get_services                    # noqa: F401,W0611
# noinspection PyUnresolvedReferences
from cornice.validators import colander_body_validator      # noqa: F401,W0611
# noinspection PyUnresolvedReferences
from cornice_swagger.swagger import CorniceSwagger          # noqa: F401,W0611
