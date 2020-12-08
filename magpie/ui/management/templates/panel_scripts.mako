<%inherit file="magpie.ui.home:templates/template.mako"/>

<!--
Renders a tab-selector header with specified options and currently selected tab.

Additional <!-> comments are added to remove automatically generated spacing whitespaces between tabs (from newlines)
that otherwise makes it troublesome to align elements using CSS. These comments are *essential* for correct display.

The function assumes it is called within a 'tabs-panel' div, which would also contain whatever the selected
'current-tab' element must display.
-->
<%def name="render_tab_selector(cur_tab_name, tab_names_urls)">
    <div class="tab-panel-selector">
        <!-- whitespace remover
        %for tab, url in tab_names_urls:
            whitespace remover --><a
                href="${url}"
                %if tab == cur_tab_name:
                    class="tab current-tab"
                %else:
                    class="tab theme"
                %endif
            >${tab}</a><!-- whitespace remover
        %endfor
        whitespace remover -->
    </div>
</%def>
