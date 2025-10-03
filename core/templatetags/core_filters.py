from django import template

register = template.Library()

@register.filter
def get_range(value):
    """
    Filter - returns a list containing range made from given value
    Usage (in template):

    {% for i in total_pages|get_range %}
      <a href="?page={{ i }}">{{ i }}</a>
    {% endfor %}

    Instead of 2000, this filter will return a list of numbers from 0 to 1999.
    """
    return range(value)
