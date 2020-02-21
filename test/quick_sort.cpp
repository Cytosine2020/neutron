#include "iostream"

using namespace std;


void quick_sort(unsigned *array, unsigned begin, unsigned end) {
    if (end - begin < 2) return;

    unsigned pivot = array[begin];
    unsigned k = begin;

    for (unsigned i = begin + 1; i < end; ++i) {
        if (array[i] < pivot) {
            array[k++] = array[i];
            array[i] = array[k];
        }
    }

    array[k] = pivot;

    quick_sort(array, begin, k);
    quick_sort(array, k + 1, end);
}

int main() {
    size_t array_size = 0;

    cout << "input length and integers: ";

    if (cin >> array_size) {
        unsigned *array = new unsigned[array_size];

        unsigned i = 0;

        while (i < array_size && cin >> array[i++]);

        if (i == array_size) {
            quick_sort(array, 0, array_size);

            for (unsigned j = 0; j < array_size; ++j)
                cout << array[j] << ' ';

            cout << endl;
        } else {
            cout << "cannot read " << array_size << " integers" << endl;
        }

        delete[] array;
    } else {
        cout << "cannot read length!" << endl;
    }
}
