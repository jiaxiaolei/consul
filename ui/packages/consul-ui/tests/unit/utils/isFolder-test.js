import { module, test } from 'qunit';
import isFolder from 'consul-ui/utils/isFolder';

module('Unit | Utils | isFolder', function () {
  test('it detects if a string ends in a slash', function (assert) {
    [
      {
        test: 'hello/world',
        expected: false,
      },
      {
        test: 'hello/world/',
        expected: true,
      },
      {
        test: '/hello/world',
        expected: false,
      },
      {
        test: '//',
        expected: true,
      },
      {
        test: undefined,
        expected: false,
      },
    ].forEach(function (item) {
      const actual = isFolder(item.test);
      assert.equal(actual, item.expected);
    });
  });
});
