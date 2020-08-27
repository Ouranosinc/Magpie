<%inherit file="ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
</%block>

<div class="error">
    <div>
        <img src="${request.static_url('magpie.ui.home:static/{}.png'.format(error_image))}"
             alt="ERROR" class="img-error">
        <span style="">
            ${error_title}
            <br>
            ${error_detail}
        </span>
        %if error_request:
            <div id="error_details">
                <div id="show_details">
                    (<button type="button" class="button-link"
                             onclick="document.getElementById('request-details').style.visibility='visible';
                                      this.parentElement.style.visibility='hidden';">
                        view original error
                    </button>)
                </div>
                <table id="request-details" class="request-details" style="visibility: hidden">
                    <thead class="theme">
                        <tr><th>Field</th><th>Value</th></tr>
                    </thead>
                    <tbody>
                    <tr><td>code</td><td>${error_code}</td></tr>
                    %for error_field, error_value in error_request.items():
                        <tr><td>${error_field.replace('_', ' ')}</td><td>${error_value}</td></tr>
                    %endfor
                    </tbody>
                </table>
            <!--<form id="view_error" action="${request.route_url('error')}">
                <input type="hidden" name="show_error" value="true">
                (<button type="submit" class="button-link">view original error</button>)
            </form>
            -->
            </div>
        %endif
    </div>
</div>
