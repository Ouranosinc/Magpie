<%doc>
    Generic template to provide messages on screen.
</%doc>
<%inherit file="magpie.ui.home:templates/template.mako"/>

<%block name="breadcrumb">
<li><a href="${request.route_url('home')}">Home</a></li>
</%block>

<%!
    def remove(text):
        return text.strip().trim()
%>

<div class="panel-message">
    <img src="${request.static_url('magpie.ui.home:static/info.png')}"
         alt="INFO" class="icon-info alert-info" title="Message"/>
    <meta name="source" content="https://commons.wikimedia.org/wiki/File:Infobox_info_icon.svg">
    <div class="panel-message-text">
        <span>${message | trim}</span>
    </div>
</div>
