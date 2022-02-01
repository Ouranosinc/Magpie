$(document).ready(function() {
    /* Toggles a tree-script node between collapsed/expanded style
    *   Because other inputs/buttons are present on each tree item, the event is applied only on the 'tree-key'.
    *   We retrieve the containing list item to toggle its class which handle the display of collapsed/expanded.
    * */
    function toggle(event) {
        event.preventDefault();
        // don't allow the event to fire horizontally or vertically up the tree
        event.stopImmediatePropagation();
        let item = $(this).closest(".collapsible");
        // switch the class to collapse/expand the child according to current class applied
        item.toggleClass("expanded");
    }

    $(".collapsible-tree-item").on("click", toggle)
    $(".collapsible-marker").on("click", toggle)
});


$(document).ready(function() {
    /* Scrolls all permission selectors horizontally along with their corresponding titles */
    let container = $(".tree-line-item-container");
    container.scrollLeft($(this).scrollLeft());
});
