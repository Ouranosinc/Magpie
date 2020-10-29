$(document).ready(function() {
    /* Toggles a tree-script node between collapsed/expanded style
    *   Because other inputs/buttons are present on each tree item, the event is applied only on the 'tree-key'.
    *   We retrieve the containing list item to toggle its class which handle the display of collapsed/expanded.
    * */
    $(".tree-key").on("click", function(e) {
        e.preventDefault();
        // don't allow the event to fire horizontally or vertically up the tree
        e.stopImmediatePropagation();
        let item = $(this).closest(".collapsible");
        // switch the class to collapse/expand the child according to current class applied
        item.toggleClass("expanded");
    })
})
